Import-Module WebAdministration

$Global:BASE_DATA  = "C:\inetpub\ftproot"
$Global:FTP_ROOT   = "C:\FTP_Users"
$Global:LOCAL_USER = "$Global:FTP_ROOT\LocalUser"
$Global:SITE_NAME  = "ServidorPracticas"

function Instalar_Requisitos {
    Write-Host "[+] Verificando roles de Windows..." -ForegroundColor Cyan
    $features = @("Web-Server", "Web-Ftp-Server", "Web-Ftp-Service")
    foreach ($f in $features) {
        $state = (Get-WindowsFeature -Name $f).InstallState
        if ($state -ne "Installed") {
            Write-Host "[+] Instalando $f..."
            Install-WindowsFeature -Name $f -IncludeManagementTools | Out-Null
            Write-Host "[OK] $f instalado." -ForegroundColor Green
        } else {
            Write-Host "[OK] $f ya instalado." -ForegroundColor Green
        }
    }
    Import-Module WebAdministration -ErrorAction Stop
}

function Configurar_Servicio_FTP {
    Instalar_Requisitos

    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"

    Write-Host "[+] Configurando estructura de directorios..."
    foreach ($dir in @("general", "reprobados", "recursadores")) {
        $path = Join-Path $Global:BASE_DATA $dir
        if (!(Test-Path $path)) { New-Item $path -ItemType Directory -Force | Out-Null }
    }

    if (!(Test-Path $Global:LOCAL_USER)) {
        New-Item $Global:LOCAL_USER -ItemType Directory -Force | Out-Null
    }

    $AnonPath = Join-Path $Global:LOCAL_USER "Public"
    if (!(Test-Path $AnonPath)) {
        New-Item $AnonPath -ItemType Directory -Force | Out-Null
    }
    if (!(Test-Path "$AnonPath\general")) {
        cmd /c "mklink /D `"$AnonPath\general`" `"$Global:BASE_DATA\general`"" | Out-Null
    }

    Write-Host "[+] Archivo de bienvenida..."
    $welcome = Join-Path $Global:BASE_DATA "general\LEEME.txt"
    if (!(Test-Path $welcome)) {
        "Bienvenido al servidor FTP Publico" | Out-File $welcome -Encoding UTF8
    }

    Write-Host "[+] Creando grupos locales..."
    foreach ($g in @("reprobados", "recursadores")) {
        if (!(Get-LocalGroup $g -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $g | Out-Null
            Write-Host "[+] Grupo $g creado." -ForegroundColor Green
        } else {
            Write-Host "[OK] Grupo $g ya existe." -ForegroundColor Green
        }
    }

    Write-Host "[+] Configurando sitio FTP en IIS..."
    if (!(Get-Website -Name $Global:SITE_NAME -ErrorAction SilentlyContinue)) {
        & $appcmd add site /name:"$Global:SITE_NAME" /bindings:"ftp://*:21" /physicalPath:"$Global:FTP_ROOT"
        Write-Host "[+] Sitio $Global:SITE_NAME creado." -ForegroundColor Green
    } else {
        Write-Host "[OK] Sitio $Global:SITE_NAME ya existe." -ForegroundColor Green
    }

    & $appcmd set site "$Global:SITE_NAME" "-ftpServer.userIsolation.mode:IsolateAllDirectories"
    & $appcmd set site "$Global:SITE_NAME" "-ftpServer.security.ssl.controlChannelPolicy:SslAllow"
    & $appcmd set site "$Global:SITE_NAME" "-ftpServer.security.ssl.dataChannelPolicy:SslAllow"
    & $appcmd set site "$Global:SITE_NAME" "-ftpServer.security.authentication.basicAuthentication.enabled:true"
    & $appcmd set site "$Global:SITE_NAME" "-ftpServer.security.authentication.anonymousAuthentication.enabled:true"

    # Limpiar reglas anteriores para evitar duplicados
    & $appcmd clear config "$Global:SITE_NAME" -section:system.ftpServer/security/authorization 2>$null

    # Anonimo SOLO LECTURA (users='?' = anonymous)
    & $appcmd set config "$Global:SITE_NAME" -section:system.ftpServer/security/authorization /+"[accessType='Allow',users='?',permissions='Read']" /commit:apphost

    # Usuarios autenticados: lectura + escritura
    & $appcmd set config "$Global:SITE_NAME" -section:system.ftpServer/security/authorization /+"[accessType='Allow',users='*',permissions='Read,Write']" /commit:apphost

    # Permisos NTFS para carpetas compartidas
    foreach ($g in @("reprobados", "recursadores")) {
        icacls "$Global:BASE_DATA\general" /grant "${g}:(OI)(CI)M" /T /Q | Out-Null
        icacls "$Global:BASE_DATA\$g"      /grant "${g}:(OI)(CI)M" /T /Q | Out-Null
    }

    # Anonimo solo puede leer /general
    icacls "$Global:BASE_DATA\general" /grant "IUSR:(OI)(CI)R" /T /Q | Out-Null

    Restart-Service ftpsvc
    Write-Host "[OK] Servicio FTP configurado correctamente." -ForegroundColor Green
}

function _Aplicar_Permisos_Usuario {
    param($User, $Grupo, $UserHome)
    icacls "$UserHome\$User"   /inheritance:r /grant "${User}:(OI)(CI)F"  /Q | Out-Null
    icacls "$UserHome\general" /grant "${User}:(OI)(CI)M" /T /Q | Out-Null
    icacls "$UserHome\$Grupo"  /grant "${User}:(OI)(CI)M" /T /Q | Out-Null
}

function Crear_Usuarios {
    $input_N = Read-Host "Cantidad de usuarios a crear"
    if (!($input_N -as [int])) { Write-Host "Numero invalido."; return }
    $Cant = [int]$input_N

    for ($i = 1; $i -le $Cant; $i++) {
        Write-Host "`n--- Usuario $i de $Cant ---"
        $User = Read-Host "Nombre de usuario"

        if (Get-LocalUser $User -ErrorAction SilentlyContinue) {
            Write-Host "[!] $User ya existe. Saltando..." -ForegroundColor Yellow
            continue
        }

        $Pass  = Read-Host "Contrasena" -AsSecureString
        $G_Opt = Read-Host "Grupo: 1) reprobados | 2) recursadores"
        $Grupo = if ($G_Opt -eq "1") { "reprobados" } else { "recursadores" }

        New-LocalUser -Name $User -Password $Pass -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
        Add-LocalGroupMember -Group $Grupo -Member $User

        $UserHome = Join-Path $Global:LOCAL_USER $User
        New-Item $UserHome -ItemType Directory -Force | Out-Null

        if (!(Test-Path "$UserHome\general")) {
            cmd /c "mklink /D `"$UserHome\general`" `"$Global:BASE_DATA\general`"" | Out-Null
        }
        if (!(Test-Path "$UserHome\$Grupo")) {
            cmd /c "mklink /D `"$UserHome\$Grupo`" `"$Global:BASE_DATA\$Grupo`"" | Out-Null
        }

        New-Item (Join-Path $UserHome $User) -ItemType Directory -Force | Out-Null

        _Aplicar_Permisos_Usuario -User $User -Grupo $Grupo -UserHome $UserHome

        Write-Host "[OK] $User configurado en grupo $Grupo." -ForegroundColor Green
    }
}

function Cambiar_Grupo {
    $User = Read-Host "Nombre del usuario"
    if (!(Get-LocalUser $User -ErrorAction SilentlyContinue)) {
        Write-Host "[!] El usuario no existe." -ForegroundColor Red
        return
    }

    $G_Opt  = Read-Host "Nuevo Grupo: 1) reprobados | 2) recursadores"
    $NuevoG = if ($G_Opt -eq "1") { "reprobados" } else { "recursadores" }
    $ViejoG = if ($G_Opt -eq "1") { "recursadores" } else { "reprobados" }

    Remove-LocalGroupMember -Group $ViejoG -Member $User -ErrorAction SilentlyContinue
    Add-LocalGroupMember    -Group $NuevoG -Member $User -ErrorAction SilentlyContinue

    $UserHome = Join-Path $Global:LOCAL_USER $User

    if (Test-Path "$UserHome\$ViejoG") {
        cmd /c "rmdir `"$UserHome\$ViejoG`"" | Out-Null
    }
    if (!(Test-Path "$UserHome\$NuevoG")) {
        cmd /c "mklink /D `"$UserHome\$NuevoG`" `"$Global:BASE_DATA\$NuevoG`"" | Out-Null
    }

    _Aplicar_Permisos_Usuario -User $User -Grupo $NuevoG -UserHome $UserHome

    Write-Host "[OK] $User movido a $NuevoG." -ForegroundColor Green
}

function Listar_Usuarios {
    Write-Host "`n--- [ USUARIOS FTP REGISTRADOS ] ---" -ForegroundColor Cyan
    Write-Host ("{0,-20} | {1,-15} | {2}" -f "USUARIO", "GRUPO", "HABILITADO")
    Write-Host ("-" * 55)

    $excluir = @("Administrator","Guest","DefaultAccount","WDAGUtilityAccount")
    $users = Get-LocalUser | Where-Object { $_.Name -notin $excluir }

    foreach ($u in $users) {
        $grupo = "Sin grupo"
        foreach ($g in @("reprobados","recursadores")) {
            $members = Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if ($members -match "\\$($u.Name)$") { $grupo = $g; break }
        }
        $habilitado = if ($u.Enabled) { "Si" } else { "No" }
        Write-Host ("{0,-20} | {1,-15} | {2}" -f $u.Name, $grupo, $habilitado)
    }
    Write-Host ("-" * 55)
}

function Verificar_Servicio {
    Write-Host "`n--- [ DIAGNOSTICO FTP ] ---" -ForegroundColor Cyan

    $svc = Get-Service ftpsvc -ErrorAction SilentlyContinue
    if ($svc.Status -eq "Running") {
        Write-Host "Estado ftpsvc : " -NoNewline; Write-Host "[ EN EJECUCION ]" -ForegroundColor Green
    } else {
        Write-Host "Estado ftpsvc : " -NoNewline; Write-Host "[ DETENIDO ]" -ForegroundColor Red
    }

    $sitio = Get-Website -Name $Global:SITE_NAME -ErrorAction SilentlyContinue
    if ($sitio) {
        $color = if ($sitio.State -eq "Started") { "Green" } else { "Red" }
        Write-Host "Sitio IIS     : " -NoNewline; Write-Host "[ $($sitio.State.ToUpper()) ]" -ForegroundColor $color
    } else {
        Write-Host "Sitio IIS     : " -NoNewline; Write-Host "[ NO EXISTE ]" -ForegroundColor Red
    }

    $puerto = netstat -an | Select-String ":21 "
    Write-Host "Puerto 21     : " -NoNewline
    if ($puerto) { Write-Host "[ ESCUCHANDO ]" -ForegroundColor Green } else { Write-Host "[ CERRADO ]" -ForegroundColor Red }

    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress
    Write-Host "IP servidor   : " -NoNewline; Write-Host "$ip" -ForegroundColor Blue
    Write-Host ("-" * 40)
}

function Gestion_UG {
    while ($true) {
        Write-Host "`n[*] GESTION DE USUARIOS Y GRUPOS"
        Write-Host "1) Crear Usuarios (Masivo)"
        Write-Host "2) Cambiar Usuario de Grupo"
        Write-Host "3) Listar Usuarios"
        Write-Host "7) Volver"
        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { Crear_Usuarios }
            "2" { Cambiar_Grupo }
            "3" { Listar_Usuarios }
            "7" { return }
            default { Write-Host "Opcion no valida." }
        }
    }
}

function Menu_Principal {
    $cfg = "C:\Windows\Temp\sec.cfg"
    secedit /export /cfg $cfg 2>$null | Out-Null
    (Get-Content $cfg) -replace "PasswordComplexity = 1", "PasswordComplexity = 0" | Set-Content $cfg
    secedit /configure /db "$env:windir\security\local.sdb" /cfg $cfg /areas SECURITYPOLICY 2>$null | Out-Null

    Configurar_Servicio_FTP

    while ($true) {
        Write-Host "`n========================================"
        Write-Host "   SERVIDOR FTP AUTOMATIZADO (IIS)      "
        Write-Host "========================================"
        Write-Host "1) Gestion de Usuarios y Grupos"
        Write-Host "2) Diagnostico del servicio"
        Write-Host "3) Reiniciar servicio (ftpsvc)"
        Write-Host "4) Salir"
        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { Gestion_UG }
            "2" { Verificar_Servicio }
            "3" { Restart-Service ftpsvc; Write-Host "[OK] ftpsvc reiniciado." -ForegroundColor Green }
            "4" { Write-Host "Saliendo..."; return }
            default { Write-Host "Opcion no valida." }
        }
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[ERROR] Ejecutar como Administrador (PowerShell como Admin)."
    exit 1
}

Menu_Principal
