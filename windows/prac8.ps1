#Requires -RunAsAdministrator
# ============================================================
#  Practica8.ps1 — Script unificado con menú interactivo
#  Gestión de Recursos y Restricción del Entorno Operativo
#  Coloca este archivo en C:\Practica8\
# ============================================================

$RutaCSV  = "C:\Users\Administrador\AdministracionSistemas\windows\usuarios.csv"
$RutaRaiz = "C:\Perfiles"

# ============================================================
#  FUNCIONES
# ============================================================

function Instalar-Requisitos {
    Write-Host "`n[1/6] Instalando FSRM y GPMC..." -ForegroundColor Cyan
    Install-WindowsFeature -Name FS-Resource-Manager, GPMC -IncludeManagementTools | Out-Null
    Write-Host "      Requisitos instalados correctamente." -ForegroundColor Green
}

# ------------------------------------------------------------
function Crear-EstructuraAD {
    Write-Host "`n[2/6] Creando OUs y Grupos en Active Directory..." -ForegroundColor Cyan
    $dominioDN = (Get-ADDomain).DistinguishedName

    # Unidades Organizativas
    foreach ($ou in @("Cuates", "No Cuates")) {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" `
                  -SearchBase $dominioDN -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $ou -Path $dominioDN `
                -ProtectedFromAccidentalDeletion $false
            Write-Host "      OU '$ou' creada." -ForegroundColor Green
        } else {
            Write-Host "      OU '$ou' ya existe, se omite." -ForegroundColor DarkGray
        }
    }

    # Grupos de seguridad
    $grupos = @(
        @{ Nombre = "Grupo_Cuates";    OU = "OU=Cuates,$dominioDN" },
        @{ Nombre = "Grupo_NoCuates";  OU = "OU=No Cuates,$dominioDN" }
    )
    foreach ($g in $grupos) {
        if (-not (Get-ADGroup -Filter "Name -eq '$($g.Nombre)'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $g.Nombre -GroupCategory Security `
                        -GroupScope Global -Path $g.OU
            Write-Host "      Grupo '$($g.Nombre)' creado." -ForegroundColor Green
        } else {
            Write-Host "      Grupo '$($g.Nombre)' ya existe, se omite." -ForegroundColor DarkGray
        }
    }
}

# ------------------------------------------------------------
function Importar-UsuariosCSV {
    Write-Host "`n[3/6] Importando usuarios y configurando horarios..." -ForegroundColor Cyan

    # Convierte horario local a los 21 bytes del atributo logonhours (UTC)
    function Crear-HorarioBytes {
        param([int]$Inicio, [int]$Fin)
        [byte[]]$bytes = New-Object byte[] 21
        for ($dia = 0; $dia -lt 7; $dia++) {
            for ($hora = 0; $hora -lt 24; $hora++) {
                $permitido = if ($Inicio -lt $Fin) {
                    ($hora -ge $Inicio -and $hora -lt $Fin)
                } else {
                    ($hora -ge $Inicio -or $hora -lt $Fin)
                }
                if ($permitido) {
                    $fechaLocal = (Get-Date -Year 2024 -Month 1 -Day 7 `
                                   -Hour 0 -Minute 0 -Second 0).AddDays($dia).AddHours($hora)
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

    [byte[]]$horasCuates   = Crear-HorarioBytes -Inicio 8  -Fin 15  # 08:00 – 15:00
    [byte[]]$horasNoCuates = Crear-HorarioBytes -Inicio 15 -Fin 2   # 15:00 – 02:00
    $dominioDN = (Get-ADDomain).DistinguishedName

    $usuarios = Import-Csv $RutaCSV
    foreach ($u in $usuarios) {
        $nUsuario = $u.usuario.Trim()
        $nPass    = $u.pass.Trim()
        $nDepto   = $u.departamento.Trim()

        $ouPath  = if ($nDepto -eq "Cuates") { "OU=Cuates,$dominioDN" } else { "OU=No Cuates,$dominioDN" }
        $grupo   = if ($nDepto -eq "Cuates") { "Grupo_Cuates" } else { "Grupo_NoCuates" }
        [byte[]]$logonHours = if ($nDepto -eq "Cuates") { $horasCuates } else { $horasNoCuates }

        $securePass = ConvertTo-SecureString $nPass -AsPlainText -Force
        $upn        = "$nUsuario@$((Get-ADDomain).Forest)"

        try {
            if (Get-ADUser -Filter {SamAccountName -eq $nUsuario} -ErrorAction SilentlyContinue) {
                Remove-ADUser -Identity $nUsuario -Confirm:$false
                Start-Sleep -Milliseconds 500
            }
            New-ADUser -Name $nUsuario `
                       -SamAccountName $nUsuario `
                       -UserPrincipalName $upn `
                       -AccountPassword $securePass `
                       -Enabled $true `
                       -Path $ouPath

            Set-ADUser -Identity $nUsuario -Replace @{ logonhours = [byte[]]$logonHours }
            Add-ADGroupMember -Identity $grupo -Members $nUsuario

            Write-Host "      [OK] $nUsuario → $nDepto" -ForegroundColor Green
        }
        catch {
            Write-Host "      [ERROR] $nUsuario : $_" -ForegroundColor Red
        }
    }
}

# ------------------------------------------------------------
function Configurar-Carpetas {
    Write-Host "`n[4/6] Creando estructura de carpetas y permisos..." -ForegroundColor Cyan
    $Dominio = (Get-ADDomain).NetBIOSName

    # Carpetas de departamento con subcarpeta General
    foreach ($dep in @("Cuates", "NoCuates")) {
        $nombreGrupo = "Grupo_$dep"
        $rutaDep     = Join-Path $RutaRaiz $dep
        $rutaGen     = Join-Path $rutaDep "General"

        if (-not (Test-Path $rutaGen)) {
            New-Item -Path $rutaGen -ItemType Directory -Force | Out-Null
        }

        $acl = Get-Acl $rutaDep
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Dominio\$nombreGrupo","Modify","ContainerInherit,ObjectInherit","None","Allow")))
        Set-Acl $rutaDep $acl
        Write-Host "      ACL aplicada: $rutaDep" -ForegroundColor Green
    }

    # Carpetas privadas por usuario
    $usuarios = Import-Csv $RutaCSV
    foreach ($u in $usuarios) {
        $nombre      = $u.usuario.Trim()
        $depLimpio   = $u.departamento.Trim() -replace " ", ""
        $rutaPrivada = Join-Path $RutaRaiz "$depLimpio\$nombre"

        if (-not (Test-Path $rutaPrivada)) {
            New-Item -Path $rutaPrivada -ItemType Directory -Force | Out-Null
        }

        $aclP = Get-Acl $rutaPrivada
        $aclP.SetAccessRuleProtection($true, $false)
        $aclP.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
        $aclP.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Dominio\$nombre","Modify","ContainerInherit,ObjectInherit","None","Allow")))
        Set-Acl $rutaPrivada $aclP
        Write-Host "      Carpeta privada: $rutaPrivada" -ForegroundColor Green
    }
}

# ------------------------------------------------------------
function Configurar-GPO-Logoff {
    Write-Host "`n[5/6] Configurando GPO de cierre forzado de sesión..." -ForegroundColor Cyan
    $dominioDN = (Get-ADDomain).DistinguishedName
    $gpoName   = "Politicas_FIM_CierreForzado"

    if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $gpoName | Out-Null
        Write-Host "      GPO '$gpoName' creada." -ForegroundColor Green
    }

    # Verificar link por separado para no fallar en re-ejecuciones
    $linkExiste = Get-GPInheritance -Target $dominioDN |
                  Select-Object -ExpandProperty GpoLinks |
                  Where-Object { $_.DisplayName -eq $gpoName }

    if (-not $linkExiste) {
        New-GPLink -Name $gpoName -Target $dominioDN | Out-Null
        Write-Host "      GPO vinculada al dominio." -ForegroundColor Green
    }

    Set-GPRegistryValue -Name $gpoName `
        -Key "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" `
        -ValueName "enableforcedlogoff" `
        -Type DWord -Value 1 | Out-Null

    Write-Host "      Cierre forzado al vencer logon hours: ACTIVO." -ForegroundColor Green
}

# ------------------------------------------------------------
function Configurar-FSRM {
    Write-Host "`n[6a] Configurando FSRM (Cuotas y Apantallamiento)..." -ForegroundColor Cyan

    $rutaCuates   = "$RutaRaiz\Cuates"
    $rutaNoCuates = "$RutaRaiz\NoCuates"

    foreach ($r in @($rutaCuates, $rutaNoCuates)) {
        if (-not (Test-Path $r)) { New-Item -Path $r -ItemType Directory -Force | Out-Null }
    }

    # 1. Limpiar y crear plantillas de cuota
    foreach ($plantilla in @("FIM_10MB","FIM_5MB")) {
        if (Get-FsrmQuotaTemplate -Name $plantilla -ErrorAction SilentlyContinue) {
            Remove-FsrmQuotaTemplate -Name $plantilla -Confirm:$false
        }
    }
    New-FsrmQuotaTemplate -Name "FIM_10MB" -Size 10MB -SoftLimit $false
    New-FsrmQuotaTemplate -Name "FIM_5MB"  -Size 5MB  -SoftLimit $false
    Write-Host "      Plantillas FIM_10MB y FIM_5MB creadas." -ForegroundColor Green

    # 2. Auto-cuotas para carpetas futuras
    foreach ($autoQ in @($rutaCuates, $rutaNoCuates)) {
        if (Get-FsrmAutoQuota -Path $autoQ -ErrorAction SilentlyContinue) {
            Remove-FsrmAutoQuota -Path $autoQ -Confirm:$false
        }
    }
    New-FsrmAutoQuota -Path $rutaCuates   -Template "FIM_10MB"
    New-FsrmAutoQuota -Path $rutaNoCuates -Template "FIM_5MB"

    # 3. Cuotas sobre carpetas de usuario ya existentes
    Get-ChildItem $rutaCuates   -Directory | ForEach-Object {
        if (Get-FsrmQuota -Path $_.FullName -ErrorAction SilentlyContinue) {
            Remove-FsrmQuota -Path $_.FullName -Confirm:$false
        }
        New-FsrmQuota -Path $_.FullName -Template "FIM_10MB"
        Write-Host "      Cuota 10MB → $($_.Name)" -ForegroundColor Green
    }
    Get-ChildItem $rutaNoCuates -Directory | ForEach-Object {
        if (Get-FsrmQuota -Path $_.FullName -ErrorAction SilentlyContinue) {
            Remove-FsrmQuota -Path $_.FullName -Confirm:$false
        }
        New-FsrmQuota -Path $_.FullName -Template "FIM_5MB"
        Write-Host "      Cuota 5MB  → $($_.Name)" -ForegroundColor Green
    }

    # 4. Grupo de archivos prohibidos con extensiones exactas de la rúbrica
    if (Get-FsrmFileGroup -Name "Archivos_Prohibidos_FIM" -ErrorAction SilentlyContinue) {
        Remove-FsrmFileGroup -Name "Archivos_Prohibidos_FIM" -Confirm:$false
    }
    New-FsrmFileGroup -Name "Archivos_Prohibidos_FIM" `
                      -IncludePattern @("*.mp3","*.mp4","*.exe","*.msi")

    # 5. Apantallamiento Activo + notificación al Event Log (evidencias para rúbrica)
    $accionEvento = New-FsrmAction -Type EventLog `
        -EventType Warning `
        -Body "FSRM BLOQUEO: [Source File Path] | Usuario: [Source Io Owner] | Fecha: [Date]"

    if (Get-FsrmFileScreen -Path $RutaRaiz -ErrorAction SilentlyContinue) {
        Remove-FsrmFileScreen -Path $RutaRaiz -Confirm:$false
    }
    New-FsrmFileScreen -Path $RutaRaiz `
                       -IncludeGroup "Archivos_Prohibidos_FIM" `
                       -Active `
                       -Notification $accionEvento

    Write-Host "      Apantallamiento activo: .mp3 .mp4 .exe .msi BLOQUEADOS." -ForegroundColor Green
    Write-Host "      Eventos de bloqueo se registran en el Event Log." -ForegroundColor Green
}

# ------------------------------------------------------------
function Configurar-AppLocker {
    Write-Host "`n[6b] Configurando AppLocker..." -ForegroundColor Cyan
    $netbios = (Get-ADDomain).NetBIOSName

    Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue

    # Política base: reglas por defecto para no bloquear el sistema
    $xmlBase = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
      Name="Permitir Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7e51"
      Name="Permitir Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
      Name="Permitir Administradores" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
    $xmlBase | Set-Content "$env:TEMP\applocker_base.xml" -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy "$env:TEMP\applocker_base.xml"
    Write-Host "      Reglas base aplicadas (Cuates pueden usar Notepad via %WINDIR%)." -ForegroundColor Green

    # Regla Hash DENY para Grupo_NoCuates — bloquea notepad.exe aunque lo renombren
    $polNotepad = Get-AppLockerFileInformation -Path "C:\Windows\System32\notepad.exe" |
                  New-AppLockerPolicy -RuleType Hash `
                                      -User "$netbios\Grupo_NoCuates" `
                                      -ErrorAction Stop

    foreach ($col in $polNotepad.RuleCollections) {
        foreach ($regla in $col) { $regla.Action = 'Deny' }
    }

    $xmlDeny = $polNotepad.ToXml()

    # Fallback: si el objeto no reflejó el cambio, forzarlo en el XML directamente
    if ($xmlDeny -notmatch 'Action="Deny"') {
        $xmlDeny = $xmlDeny -replace 'Action="Allow"', 'Action="Deny"'
        Write-Host "      [INFO] Action=Deny forzado vía XML." -ForegroundColor Yellow
    }

    $xmlDeny | Set-Content "$env:TEMP\applocker_deny_notepad.xml" -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy "$env:TEMP\applocker_deny_notepad.xml" -Merge

    Write-Host "      Notepad BLOQUEADO por Hash para Grupo_NoCuates." -ForegroundColor Green

    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\AppIDSvc" `
                     -Name "Start" -Value 2 -ErrorAction SilentlyContinue
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "      Servicio AppIDSvc iniciado." -ForegroundColor Green
}

# ------------------------------------------------------------
function Ejecutar-Todo {
    if (-not (Validar-CSV)) { return }
    Instalar-Requisitos
    Crear-EstructuraAD
    Importar-UsuariosCSV
    Configurar-Carpetas
    Configurar-GPO-Logoff
    Configurar-FSRM
    Configurar-AppLocker

    Write-Host "`nAplicando gpupdate /force..." -ForegroundColor Cyan
    gpupdate /force | Out-Null

    Write-Host "`n=========================================="  -ForegroundColor Yellow
    Write-Host "   PRÁCTICA 8 CONFIGURADA CON ÉXITO      "   -ForegroundColor Yellow
    Write-Host "=========================================="    -ForegroundColor Yellow
    Write-Host "  C:\Perfiles\Cuates\    → Cuota 10MB"        -ForegroundColor White
    Write-Host "  C:\Perfiles\NoCuates\  → Cuota 5MB"         -ForegroundColor White
    Write-Host "  AppLocker: Notepad bloqueado a NoCuates"     -ForegroundColor White
    Write-Host "  FSRM: Bloquea .mp3 .mp4 .exe .msi"          -ForegroundColor White
    Write-Host "  GPO: Cierre forzado al vencer horario"       -ForegroundColor White
}

# ------------------------------------------------------------
function Validar-CSV {
    if (-not (Test-Path $RutaCSV)) {
        Write-Host "[ERROR] No se encontró: $RutaCSV" -ForegroundColor Red
        Write-Host "        Formato requerido: usuario,pass,departamento" -ForegroundColor Yellow
        return $false
    }
    $fila = Import-Csv $RutaCSV | Select-Object -First 1
    $cols = $fila.PSObject.Properties.Name
    if (-not ($cols -contains "usuario" -and $cols -contains "pass" -and $cols -contains "departamento")) {
        Write-Host "[ERROR] El CSV debe tener columnas: usuario, pass, departamento" -ForegroundColor Red
        return $false
    }
    return $true
}

# ============================================================
#  MENÚ PRINCIPAL
# ============================================================

function Mostrar-Menu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Yellow
    Write-Host "       PRÁCTICA 8 — MENÚ PRINCIPAL        " -ForegroundColor Yellow
    Write-Host "==========================================" -ForegroundColor Yellow
    Write-Host "  CSV actual : $RutaCSV"                    -ForegroundColor DarkGray
    Write-Host "  Dominio    : $((Get-ADDomain).DNSRoot)"   -ForegroundColor DarkGray
    Write-Host "------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [1]  Instalar Requisitos (FSRM + GPMC)"   -ForegroundColor Cyan
    Write-Host "  [2]  Crear Estructura AD (OUs + Grupos)"  -ForegroundColor Cyan
    Write-Host "  [3]  Importar Usuarios del CSV"           -ForegroundColor Cyan
    Write-Host "  [4]  Crear Carpetas y Permisos"           -ForegroundColor Cyan
    Write-Host "  [5]  Configurar GPO Cierre Forzado"       -ForegroundColor Cyan
    Write-Host "  [6]  Configurar FSRM (Cuotas + Pantalla)" -ForegroundColor Cyan
    Write-Host "  [7]  Configurar AppLocker"                -ForegroundColor Cyan
    Write-Host "------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [A]  EJECUTAR TODO (1 al 7)"              -ForegroundColor Green
    Write-Host "  [G]  Forzar gpupdate /force"              -ForegroundColor Magenta
    Write-Host "  [S]  Salir"                               -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Yellow
    Write-Host ""
}

# --- Bucle del menú ---
do {
    Mostrar-Menu
    $opcion = Read-Host "Selecciona una opcion"

    switch ($opcion.ToUpper()) {
        "1" { Instalar-Requisitos }
        "2" { Crear-EstructuraAD }
        "3" { if (Validar-CSV) { Importar-UsuariosCSV } }
        "4" { if (Validar-CSV) { Configurar-Carpetas } }
        "5" { Configurar-GPO-Logoff }
        "6" { Configurar-FSRM }
        "7" { Configurar-AppLocker }
        "A" { Ejecutar-Todo }
        "G" {
            Write-Host "`nEjecutando gpupdate /force..." -ForegroundColor Cyan
            gpupdate /force
        }
        "S" {
            Write-Host "`nSaliendo..." -ForegroundColor Red
        }
        default {
            Write-Host "`nOpción no válida. Intenta de nuevo." -ForegroundColor Red
        }
    }

    if ($opcion.ToUpper() -ne "S") {
        Write-Host "`nPresiona ENTER para volver al menú..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }

} while ($opcion.ToUpper() -ne "S")
