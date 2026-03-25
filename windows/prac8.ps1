
# ======================== VARIABLES GLOBALES ========================
$rutaCSV  = "C:\Practica8\usuarios.csv"

# ======================== FUNCIONES DE APOYO ========================

function Mostrar-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  #############################################" -ForegroundColor DarkCyan
    Write-Host "  #                                           #" -ForegroundColor DarkCyan
    Write-Host "  #        PRACTICA 8 - WINDOWS SERVER        #" -ForegroundColor Cyan
    Write-Host "  #     Gestion de Recursos y Politicas GPO   #" -ForegroundColor Cyan
    Write-Host "  #                                           #" -ForegroundColor DarkCyan
    Write-Host "  #############################################" -ForegroundColor DarkCyan
    Write-Host ""
}

function Mostrar-Menu {
    Mostrar-Banner
    Write-Host "  Selecciona una opcion:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1]  Instalar Requisitos (FSRM + GPMC)"          -ForegroundColor Yellow
    Write-Host "  [2]  Crear Estructura AD (OUs + Grupos)"          -ForegroundColor Yellow
    Write-Host "  [3]  Importar Usuarios desde CSV"                 -ForegroundColor Yellow
    Write-Host "  [4]  Configurar Carpetas y Permisos NTFS"         -ForegroundColor Yellow
    Write-Host "  [5]  Configurar GPO Cierre Forzado de Sesion"     -ForegroundColor Yellow
    Write-Host "  [6]  Configurar FSRM (Cuotas + Apantallamiento)"  -ForegroundColor Yellow
    Write-Host "  [7]  Configurar AppLocker"                        -ForegroundColor Yellow
    Write-Host "  [8]  Ejecutar TODO en orden automatico"           -ForegroundColor Green
    Write-Host "  [9]  Forzar actualizacion de politicas (gpupdate)" -ForegroundColor Cyan
    Write-Host "  [0]  Salir"                                        -ForegroundColor Red
    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor DarkGray
}

function Pausar {
    Write-Host ""
    Write-Host "  Presiona cualquier tecla para volver al menu..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Verificar-Administrador {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host ""
        Write-Host "  [ERROR] Este script debe ejecutarse como Administrador." -ForegroundColor Red
        Write-Host "  Haz clic derecho en PowerShell > Ejecutar como administrador." -ForegroundColor Yellow
        exit 1
    }
}

function Verificar-CSV {
    if (-not (Test-Path $rutaCSV)) {
        Write-Host ""
        Write-Host "  [ERROR] No se encontro el archivo CSV en: $rutaCSV" -ForegroundColor Red
        Write-Host "  Crea el archivo antes de continuar." -ForegroundColor Yellow
        Write-Host "  Estructura requerida: usuario, pass, departamento" -ForegroundColor Gray
        return $false
    }
    return $true
}

# ======================== FUNCION 1: INSTALAR REQUISITOS ========================

function Instalar-Requisitos {
    Write-Host ""
    Write-Host "  [1/8] Instalando FSRM y GPMC..." -ForegroundColor Cyan
    Install-WindowsFeature -Name FS-Resource-Manager, GPMC -IncludeManagementTools | Out-Null
    Write-Host "  [OK] FSRM y GPMC instalados correctamente." -ForegroundColor Green
}

# ======================== FUNCION 2: ESTRUCTURA AD ========================

function Crear-EstructuraAD {
    $dominioDN = (Get-ADDomain).DistinguishedName
    Write-Host ""
    Write-Host "  [2/8] Verificando/Creando Unidades Organizativas y Grupos..." -ForegroundColor Cyan

    # --- Crear OUs ---
    $ous = @("Cuates", "No Cuates")
    foreach ($ou in $ous) {
        $existe = Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue
        if (-not $existe) {
            New-ADOrganizationalUnit -Name $ou -Path $dominioDN -ProtectedFromAccidentalDeletion $false
            Write-Host "  [OK] OU '$ou' creada." -ForegroundColor Green
        } else {
            Write-Host "  [INFO] OU '$ou' ya existe. Omitiendo." -ForegroundColor Gray
        }
    }

    # --- Crear Grupos de Seguridad ---
    $grupos = @(
        @{ Nombre = "Grupo_Cuates";    OU = "OU=Cuates,$dominioDN" },
        @{ Nombre = "Grupo_NoCuates";  OU = "OU=No Cuates,$dominioDN" }
    )
    foreach ($g in $grupos) {
        $existe = Get-ADGroup -Filter "Name -eq '$($g.Nombre)'" -ErrorAction SilentlyContinue
        if (-not $existe) {
            New-ADGroup -Name $g.Nombre -GroupCategory Security -GroupScope Global -Path $g.OU
            Write-Host "  [OK] Grupo '$($g.Nombre)' creado." -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Grupo '$($g.Nombre)' ya existe. Omitiendo." -ForegroundColor Gray
        }
    }
}

# ======================== FUNCION 3: IMPORTAR USUARIOS CSV ========================

function Importar-UsuariosCSV {
    Write-Host ""
    Write-Host "  [3/8] Importando usuarios desde CSV y configurando horarios..." -ForegroundColor Cyan

    if (-not (Verificar-CSV)) { return }

    $dominioDN = (Get-ADDomain).DistinguishedName

    # Calcula el arreglo de bytes de horario con correccion UTC
    function Crear-HorarioBytes {
        param([int]$Inicio, [int]$Fin)
        [byte[]]$bytes = New-Object byte[] 21
        for ($dia = 0; $dia -lt 7; $dia++) {
            for ($hora = 0; $hora -lt 24; $hora++) {
                $permitido = $false
                if ($Inicio -lt $Fin) {
                    if ($hora -ge $Inicio -and $hora -lt $Fin) { $permitido = $true }
                } else {
                    if ($hora -ge $Inicio -or $hora -lt $Fin)  { $permitido = $true }
                }
                if ($permitido) {
                    $fechaLocal = (Get-Date -Year 2024 -Month 1 -Day 7 -Hour 0 -Minute 0 -Second 0).AddDays($dia).AddHours($hora)
                    $fechaUTC   = $fechaLocal.ToUniversalTime()
                    $diaUTC     = [int]$fechaUTC.DayOfWeek
                    $horaUTC    = $fechaUTC.Hour
                    $byteIndex  = ($diaUTC * 3) + [Math]::Floor($horaUTC / 8)
                    $bitIndex   = $horaUTC % 8
                    $bytes[$byteIndex] = $bytes[$byteIndex] -bor (1 -shl $bitIndex)
                }
            }
        }
        return $bytes
    }

    [byte[]]$horasCuates   = Crear-HorarioBytes -Inicio 8  -Fin 15   # 8AM - 3PM
    [byte[]]$horasNoCuates = Crear-HorarioBytes -Inicio 15 -Fin 2    # 3PM - 2AM

    $usuarios = Import-Csv $rutaCSV
    $total    = $usuarios.Count
    $contador = 0

    foreach ($u in $usuarios) {
        $contador++
        $nUsuario = $u.usuario
        $nPass    = $u.pass
        $nDepto   = $u.departamento

        $ouPath            = if ($nDepto -eq "Cuates") { "OU=Cuates,$dominioDN" } else { "OU=No Cuates,$dominioDN" }
        $logonHoursToApply = if ($nDepto -eq "Cuates") { $horasCuates } else { $horasNoCuates }
        $grupoSeguridad    = if ($nDepto -eq "Cuates") { "Grupo_Cuates" } else { "Grupo_NoCuates" }

        $password = ConvertTo-SecureString $nPass -AsPlainText -Force
        $upn      = "$nUsuario@$((Get-ADDomain).Forest)"

        # Eliminar usuario previo si existe
        $existe = Get-ADUser -Filter { SamAccountName -eq $nUsuario } -ErrorAction SilentlyContinue
        if ($existe) {
            Remove-ADUser -Identity $nUsuario -Confirm:$false
        }

        New-ADUser `
            -Name              $nUsuario `
            -SamAccountName    $nUsuario `
            -UserPrincipalName $upn `
            -AccountPassword   $password `
            -Enabled           $true `
            -Path              $ouPath

        Set-ADUser -Identity $nUsuario -Replace @{ logonhours = [byte[]]$logonHoursToApply } -ErrorAction Continue
        Add-ADGroupMember -Identity $grupoSeguridad -Members $nUsuario -ErrorAction SilentlyContinue

        Write-Host "  [$contador/$total] Usuario '$nUsuario' creado en '$nDepto'." -ForegroundColor Green
    }

    Write-Host "  [OK] $total usuarios importados exitosamente." -ForegroundColor Green
}

# ======================== FUNCION 4: CARPETAS Y PERMISOS NTFS ========================

function Configurar-CarpetasNTFS {
    Write-Host ""
    Write-Host "  [4/8] Configurando carpetas y permisos NTFS por usuario..." -ForegroundColor Cyan

    if (-not (Verificar-CSV)) { return }

    $RutaRaiz = "C:\Perfiles"
    $Dominio  = (Get-ADDomain).NetBIOSName
    $usuarios = Import-Csv $rutaCSV

    # --- Carpetas generales por departamento ---
    $departamentos = @("Cuates", "NoCuates")
    foreach ($dep in $departamentos) {
        $nombreGrupoAD = "Grupo_$dep"
        $rutaDep       = Join-Path $RutaRaiz $dep
        $rutaGen       = Join-Path $rutaDep "General"

        if (-not (Test-Path $rutaGen)) {
            New-Item -Path $rutaGen -ItemType Directory -Force | Out-Null
        }

        $acl = Get-Acl $rutaDep
        $acl.SetAccessRuleProtection($true, $false)

        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $groupRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Dominio\$nombreGrupoAD", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

        $acl.SetAccessRule($adminRule)
        $acl.SetAccessRule($groupRule)
        Set-Acl $rutaDep $acl
        Write-Host "  [OK] Permisos de grupo aplicados en: $rutaDep" -ForegroundColor Green
    }

    # --- Carpetas privadas por usuario ---
    foreach ($u in $usuarios) {
        $nombre    = $u.usuario
        $depLimpio = $u.departamento -replace " ", ""
        $rutaPriv  = Join-Path $RutaRaiz "$depLimpio\$nombre"

        if (-not (Test-Path $rutaPriv)) {
            New-Item -Path $rutaPriv -ItemType Directory -Force | Out-Null
        }

        $aclPriv = Get-Acl $rutaPriv
        $aclPriv.SetAccessRuleProtection($true, $false)

        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $userRule  = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Dominio\$nombre", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

        $aclPriv.SetAccessRule($adminRule)
        $aclPriv.SetAccessRule($userRule)
        Set-Acl $rutaPriv $aclPriv

        Write-Host "  [OK] Carpeta privada lista: $rutaPriv" -ForegroundColor Green
    }
}

# ======================== FUNCION 5: GPO CIERRE FORZADO ========================

function Configurar-GPO-Logoff {
    $dominioDN = (Get-ADDomain).DistinguishedName
    Write-Host ""
    Write-Host "  [5/8] Aplicando GPO de cierre forzado de sesion..." -ForegroundColor Cyan

    $gpoName = "Politicas_FIM_CierreForzado"

    if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $gpoName | New-GPLink -Target $dominioDN | Out-Null
        Write-Host "  [OK] GPO '$gpoName' creada y vinculada al dominio." -ForegroundColor Green
    } else {
        Write-Host "  [INFO] GPO '$gpoName' ya existe. Actualizando valor." -ForegroundColor Gray
    }

    Set-GPRegistryValue `
        -Name      $gpoName `
        -Key       "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" `
        -ValueName "enableforcedlogoff" `
        -Type      DWord `
        -Value     1 | Out-Null

    Write-Host "  [OK] GPO de cierre forzado activa en el dominio." -ForegroundColor Green
}

# ======================== FUNCION 6: FSRM ========================

function Configurar-FSRM {
    Write-Host ""
    Write-Host "  [6/8] Configurando FSRM: Cuotas y Apantallamiento de Archivos..." -ForegroundColor Cyan

    $rutaBase     = "C:\Perfiles"
    $rutaCuates   = "C:\Perfiles\Cuates"
    $rutaNoCuates = "C:\Perfiles\NoCuates"

    # --- Asegurar directorios ---
    foreach ($ruta in @($rutaCuates, $rutaNoCuates)) {
        if (-not (Test-Path $ruta)) {
            New-Item -Path $ruta -ItemType Directory -Force | Out-Null
        }
    }

    # --- Limpieza previa ---
    Write-Host "  Limpiando configuracion FSRM previa..." -ForegroundColor Yellow
    & dirquota quota    delete /path:$rutaBase /quiet /recursive 2>$null
    & dirquota autoquota delete /path:$rutaBase /quiet /recursive 2>$null

    foreach ($ruta in @($rutaBase, $rutaCuates, $rutaNoCuates)) {
        Get-FsrmFileScreen -Path $ruta -ErrorAction SilentlyContinue |
            Remove-FsrmFileScreen -Confirm:$false -ErrorAction SilentlyContinue
    }

    # --- Grupo personalizado de extensiones bloqueadas ---
    Write-Host "  Creando grupo de extensiones bloqueadas: .exe .msi .mp3 .mp4..." -ForegroundColor Yellow
    $nombreGrupo = "Bloqueados_Practica8"

    Get-FsrmFileGroup -Name $nombreGrupo -ErrorAction SilentlyContinue |
        Remove-FsrmFileGroup -Confirm:$false -ErrorAction SilentlyContinue

    New-FsrmFileGroup `
        -Name           $nombreGrupo `
        -IncludePattern @("*.exe", "*.msi", "*.mp3", "*.mp4") `
        -ErrorAction    Stop | Out-Null

    # --- Apantallamiento activo (Active Screening) ---
    New-FsrmFileScreen `
        -Path         $rutaBase `
        -IncludeGroup $nombreGrupo `
        -Active `
        -ErrorAction  Stop | Out-Null

    Write-Host "  [OK] File Screen activo: bloqueados .exe / .msi / .mp3 / .mp4" -ForegroundColor Green

    # --- Auto-cuotas para carpetas futuras ---
    Write-Host "  Aplicando auto-cuotas..." -ForegroundColor Yellow
    & dirquota autoquota add /path:$rutaCuates   /limit:10mb /type:hard | Out-Null
    & dirquota autoquota add /path:$rutaNoCuates /limit:5mb  /type:hard | Out-Null

    # --- Cuotas manuales para usuarios ya existentes ---
    Write-Host "  Sincronizando cuotas en carpetas existentes..." -ForegroundColor Yellow
    $cc = 0; $cn = 0

    if (Test-Path $rutaCuates) {
        Get-ChildItem $rutaCuates -Directory | ForEach-Object {
            & dirquota quota add /path:"$($_.FullName)" /limit:10mb /type:hard | Out-Null
            $cc++
        }
    }
    if (Test-Path $rutaNoCuates) {
        Get-ChildItem $rutaNoCuates -Directory | ForEach-Object {
            & dirquota quota add /path:"$($_.FullName)" /limit:5mb /type:hard | Out-Null
            $cn++
        }
    }

    Write-Host "  [OK] Cuotas: $cc carpetas Cuates (10MB) | $cn carpetas NoCuates (5MB)" -ForegroundColor Green
    Write-Host "  [OK] FSRM configurado correctamente." -ForegroundColor Green
}

# ======================== FUNCION 7: APPLOCKER ========================

function Configurar-AppLocker {
    Write-Host ""
    Write-Host "  [7/8] Configurando AppLocker (Notepad bloqueado por Hash para NoCuates)..." -ForegroundColor Cyan

    Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue

    # Reglas base que permiten Windows y Program Files a todos
    $xmlBase = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="Permitir Program Files" Description="Regla por defecto" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7e51" Name="Permitir Windows" Description="Regla por defecto" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="Permitir Administradores" Description="Regla por defecto" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

    $rutaXML = "$env:TEMP\applocker_base.xml"
    $xmlBase | Out-File -FilePath $rutaXML -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy $rutaXML -ErrorAction SilentlyContinue

    # Regla de DENEGACION por Hash para Notepad al grupo NoCuates
    $netbios    = (Get-ADDomain).NetBIOSName
    $polNotepad = Get-AppLockerFileInformation -Path "C:\Windows\System32\notepad.exe" |
                  New-AppLockerPolicy -RuleType Hash -User "$netbios\Grupo_NoCuates" -ErrorAction SilentlyContinue

    if ($polNotepad) {
        foreach ($coleccion in $polNotepad.RuleCollections) {
            foreach ($regla in $coleccion) {
                $regla.Action = 'Deny'
            }
        }
        Set-AppLockerPolicy -PolicyObject $polNotepad -Merge | Out-Null
        Write-Host "  [OK] Notepad bloqueado por Hash para Grupo_NoCuates." -ForegroundColor Green
    } else {
        Write-Host "  [ADVERTENCIA] No se pudo generar la regla de Hash para Notepad." -ForegroundColor Yellow
    }

    # Habilitar e iniciar el servicio AppID
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value 2 -ErrorAction SilentlyContinue
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue

    Write-Host "  [OK] AppLocker configurado correctamente." -ForegroundColor Green
}

# ======================== FUNCION 8: EJECUTAR TODO ========================

function Ejecutar-Todo {
    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor Yellow
    Write-Host "  EJECUTANDO CONFIGURACION COMPLETA..." -ForegroundColor Yellow
    Write-Host "  =============================================" -ForegroundColor Yellow

    if (-not (Verificar-CSV)) {
        Write-Host "  [ERROR] No se puede continuar sin el CSV." -ForegroundColor Red
        return
    }

    Instalar-Requisitos
    Crear-EstructuraAD
    Importar-UsuariosCSV
    Configurar-CarpetasNTFS
    Configurar-GPO-Logoff
    Configurar-FSRM
    Configurar-AppLocker

    Write-Host ""
    Write-Host "  Forzando actualizacion de politicas..." -ForegroundColor Cyan
    gpupdate /force | Out-Null

    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor Yellow
    Write-Host "  PRACTICA 8 CONFIGURADA CON EXITO" -ForegroundColor Green
    Write-Host "  =============================================" -ForegroundColor Yellow
}

# ======================== FUNCION 9: GPUPDATE ========================

function Forzar-GPUpdate {
    Write-Host ""
    Write-Host "  Ejecutando gpupdate /force ..." -ForegroundColor Cyan
    gpupdate /force
    Write-Host "  [OK] Politicas actualizadas." -ForegroundColor Green
}

# ======================== BUCLE PRINCIPAL DEL MENU ========================

Verificar-Administrador

do {
    Mostrar-Menu
    $opcion = Read-Host "  Ingresa tu opcion"

    switch ($opcion) {
        "1" { Instalar-Requisitos;       Pausar }
        "2" { Crear-EstructuraAD;        Pausar }
        "3" { Importar-UsuariosCSV;      Pausar }
        "4" { Configurar-CarpetasNTFS;   Pausar }
        "5" { Configurar-GPO-Logoff;     Pausar }
        "6" { Configurar-FSRM;           Pausar }
        "7" { Configurar-AppLocker;      Pausar }
        "8" { Ejecutar-Todo;             Pausar }
        "9" { Forzar-GPUpdate;           Pausar }
        "0" {
            Write-Host ""
            Write-Host "  Saliendo..." -ForegroundColor DarkGray
        }
        default {
            Write-Host ""
            Write-Host "  [!] Opcion invalida. Intenta de nuevo." -ForegroundColor Red
            Pausar
        }
    }
} while ($opcion -ne "0")
