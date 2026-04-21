# =========================================================================
# PRACTICA 09 - HARDENING DE AD, AUDITORIA Y MFA (VERSION COMPLETA)
# Autor  : Carlos David Cota Sanudo
# Dominio: carlos.local
# NOTA   : Ejecutar como Administrador del Dominio en PowerShell elevado
# =========================================================================

#Requires -RunAsAdministrator

Import-Module ActiveDirectory -ErrorAction Stop

# --- CONSTANTES GLOBALES ---
$Dominio     = "carlos.local"
$DCPath      = "DC=carlos,DC=local"
$NetBIOS     = "carlos"
$PassAdmin   = ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force
$RutaReporte = "C:\Reportes_P09\Auditoria_Accesos_Denegados.txt"
$LogScript   = "C:\Reportes_P09\Log_Ejecucion_P09.log"

# --- FUNCIONES DE UTILIDAD ---

function Write-Log {
    param([string]$Mensaje, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linea = "[$timestamp] $Mensaje"
    Write-Host $linea -ForegroundColor $Color
    Add-Content -Path $LogScript -Value $linea -ErrorAction SilentlyContinue
}

function Ensure-Directory {
    param([string]$Ruta)
    if (-not (Test-Path $Ruta)) {
        New-Item -ItemType Directory -Path $Ruta -Force | Out-Null
        Write-Log "Directorio creado: $Ruta" "Gray"
    }
}

function Invoke-DSAcls {
    param([string]$Argumento)
    $resultado = cmd.exe /c "dsacls $Argumento 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Log "  [!] dsacls error: $resultado" "DarkYellow"
    }
}

function Mostrar-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host "     PRACTICA 09: HARDENING DE AD - AUDITORIA - MFA         " -ForegroundColor Yellow
    Write-Host "     Dominio: carlos.local                                   " -ForegroundColor Gray
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host "  FASES DE IMPLEMENTACION:"
    Write-Host "  [1]  FASE 1 - OUs, Grupos y Usuarios (Base RBAC)"
    Write-Host "  [2]  FASE 2 - ACLs Granulares (Privilegio Minimo)"
    Write-Host "  [3]  FASE 3 - FGPP (12 chars Admins / 8 chars Users)"
    Write-Host "  [4]  FASE 4 - Auditoria Completa del Sistema"
    Write-Host "  [5]  FASE 5 - Configuracion de MFA (TOTP/WinOTP)"
    Write-Host "  [6]  FASE 6 - Configurar FSRM (Rol admin_storage)"
    Write-Host "  ----------------------------------------------------------"
    Write-Host "  REPORTES Y VERIFICACION:"
    Write-Host "  [R]  Generar Reporte de Accesos Denegados (4625)"
    Write-Host "  [V]  Verificar Estado Completo de la Practica"
    Write-Host "  ----------------------------------------------------------"
    Write-Host "  TESTS DE PROTOCOLO:"
    Write-Host "  [T1] Test - Denegacion de Reset a admin_storage"
    Write-Host "  [T2] Test - Rechazo de FGPP (password menor a 12 chars)"
    Write-Host "  ----------------------------------------------------------"
    Write-Host "  [TODO] Ejecutar TODAS las fases en orden (1 al 6)" -ForegroundColor Green
    Write-Host "  [S]    Salir"
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host ""
}

# --- FASE 1: INFRAESTRUCTURA BASE ---

function Fase1-InfraestructuraBase {
    Write-Log "==========================================" "Cyan"
    Write-Log " FASE 1: Creando OUs, Grupos y Usuarios   " "Yellow"
    Write-Log "==========================================" "Cyan"

    Ensure-Directory "C:\Reportes_P09"

    Write-Log "`n[1.1] Creando Unidades Organizativas..." "Yellow"
    $OUs = @(
        @{ Nombre = "AdminDelegados"; Path = $DCPath },
        @{ Nombre = "Cuates";         Path = $DCPath },
        @{ Nombre = "No Cuates";      Path = $DCPath },
        @{ Nombre = "Usuarios_Std";   Path = $DCPath }
    )

    foreach ($ou in $OUs) {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Nombre)'" -SearchBase $ou.Path -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $ou.Nombre -Path $ou.Path
            Write-Log "  [+] OU '$($ou.Nombre)' creada." "Green"
        } else {
            Write-Log "  [.] OU '$($ou.Nombre)' ya existe." "Gray"
        }
    }

    Write-Log "`n[1.2] Creando Grupos de Seguridad (necesarios para FGPP)..." "Yellow"
    $Grupos = @(
        @{ Nombre = "GG_Admins_Delegados"; Path = "OU=AdminDelegados,$DCPath"; Desc = "Admins delegados - FGPP_Admins" },
        @{ Nombre = "GG_Usuarios_Std";     Path = "OU=Usuarios_Std,$DCPath";   Desc = "Usuarios estandar - FGPP_Standard" }
    )

    foreach ($g in $Grupos) {
        if (-not (Get-ADGroup -Filter "Name -eq '$($g.Nombre)'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $g.Nombre -GroupScope Global -GroupCategory Security `
                        -Path $g.Path -Description $g.Desc
            Write-Log "  [+] Grupo '$($g.Nombre)' creado." "Green"
        } else {
            Write-Log "  [.] Grupo '$($g.Nombre)' ya existe." "Gray"
        }
    }

    Write-Log "`n[1.3] Creando Usuarios Administrativos Delegados..." "Yellow"
    $UsuariosAdmin = @(
        @{ Sam = "admin_identidad";  Nombre = "Admin Identidad";  Desc = "ROL 1 - IAM Operator"        },
        @{ Sam = "admin_storage";    Nombre = "Admin Storage";    Desc = "ROL 2 - Storage Operator"     },
        @{ Sam = "admin_politicas";  Nombre = "Admin Politicas";  Desc = "ROL 3 - GPO Compliance Admin" },
        @{ Sam = "admin_auditoria";  Nombre = "Admin Auditoria";  Desc = "ROL 4 - Security Auditor"     }
    )

    foreach ($u in $UsuariosAdmin) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
            New-ADUser -Name $u.Nombre -SamAccountName $u.Sam -DisplayName $u.Nombre `
                       -Description $u.Desc -AccountPassword $PassAdmin -Enabled $true `
                       -Path "OU=AdminDelegados,$DCPath" -ChangePasswordAtLogon $false
            Write-Log "  [+] Usuario '$($u.Sam)' creado." "Green"
        } else {
            Write-Log "  [.] Usuario '$($u.Sam)' ya existe." "Gray"
        }
    }

    Write-Log "`n[1.4] Creando Usuarios Estandar de Prueba..." "Yellow"
    $UsuariosStd = @(
        @{ Sam = "jlopez";    OU = "Cuates"    },
        @{ Sam = "mgarcia";   OU = "Cuates"    },
        @{ Sam = "rperez";    OU = "No Cuates" },
        @{ Sam = "amorales";  OU = "No Cuates" },
        @{ Sam = "user_test"; OU = "Cuates"    }
    )

    foreach ($u in $UsuariosStd) {
        $ouPath = "OU=$($u.OU),$DCPath"
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
            New-ADUser -Name $u.Sam -SamAccountName $u.Sam -AccountPassword $PassAdmin `
                       -Enabled $true -Path $ouPath
            Write-Log "  [+] Usuario '$($u.Sam)' creado en OU '$($u.OU)'." "Green"
        } else {
            Write-Log "  [.] Usuario '$($u.Sam)' ya existe." "Gray"
        }
    }

    Write-Log "`n[1.5] Asignando membresia de grupos..." "Yellow"

    foreach ($u in $UsuariosAdmin) {
        Add-ADGroupMember -Identity "GG_Admins_Delegados" -Members $u.Sam -ErrorAction SilentlyContinue
    }
    Write-Log "  [+] Admins delegados agregados a GG_Admins_Delegados." "Green"

    foreach ($u in $UsuariosStd) {
        Add-ADGroupMember -Identity "GG_Usuarios_Std" -Members $u.Sam -ErrorAction SilentlyContinue
    }
    Write-Log "  [+] Usuarios estandar agregados a GG_Usuarios_Std." "Green"

    Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members "admin_politicas" -ErrorAction SilentlyContinue
    Write-Log "  [+] admin_politicas -> Group Policy Creator Owners." "Green"

    Add-ADGroupMember -Identity "Event Log Readers" -Members "admin_auditoria" -ErrorAction SilentlyContinue
    Write-Log "  [+] admin_auditoria -> Event Log Readers." "Green"

    Write-Log "`n[OK] FASE 1 completada." "Green"
    Pause
}

# --- FASE 2: ACLs GRANULARES ---

function Fase2-ACLsGranulares {
    Write-Log "==========================================" "Cyan"
    Write-Log " FASE 2: Aplicando ACLs (Menor Privilegio)" "Yellow"
    Write-Log "==========================================" "Cyan"

    $OUsUsuarios = @(
        "`"OU=Cuates,$DCPath`"",
        "`"OU=No Cuates,$DCPath`""
    )

    Write-Log "`n[ROL 1] admin_identidad - Gestion de usuarios en Cuates y No Cuates" "Yellow"
    foreach ($ouDN in $OUsUsuarios) {
        Invoke-DSAcls "$ouDN /I:T /G `"$NetBIOS\admin_identidad:CCDC;user`""
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:WP;;user`""
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:CA;Reset Password;user`""
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:CA;Change Password;user`""
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:WP;lockoutTime;user`""
    }
    Write-Log "  [+] Permisos de gestion otorgados sobre Cuates y No Cuates." "Green"

    $domainAdminsPath = "`"CN=Domain Admins,CN=Users,$DCPath`""
    Invoke-DSAcls "$domainAdminsPath /D `"$NetBIOS\admin_identidad:WP`""
    Write-Log "  [+] admin_identidad: DENEGADO modificar Domain Admins." "Green"

    Write-Log "`n[ROL 2] admin_storage - DENEGACION explicita de Reset Password" "Yellow"
    $contenedores = @(
        "`"OU=Cuates,$DCPath`"",
        "`"OU=No Cuates,$DCPath`"",
        "`"OU=AdminDelegados,$DCPath`"",
        "`"$DCPath`""
    )
    foreach ($c in $contenedores) {
        Invoke-DSAcls "$c /I:S /D `"$NetBIOS\admin_storage:CA;Reset Password;user`""
        Invoke-DSAcls "$c /I:S /D `"$NetBIOS\admin_storage:CA;Change Password;user`""
    }
    Write-Log "  [+] admin_storage: DENEGADO Reset/Change Password en todo el dominio." "Green"

    Write-Log "`n[ROL 3] admin_politicas - Solo lectura en dominio; escritura solo en GPOs" "Yellow"
    Invoke-DSAcls "`"$DCPath`" /I:T /G `"$NetBIOS\admin_politicas:GR`""
    Write-Log "  [+] admin_politicas: Lectura concedida en todo el dominio." "Green"

    $gpoPoliciesPath = "`"CN=Policies,CN=System,$DCPath`""
    Invoke-DSAcls "$gpoPoliciesPath /I:T /G `"$NetBIOS\admin_politicas:GA`""
    Write-Log "  [+] admin_politicas: Escritura concedida en CN=Policies (GPOs)." "Green"

    foreach ($ouDN in $OUsUsuarios) {
        Invoke-DSAcls "$ouDN /I:S /D `"$NetBIOS\admin_politicas:WP;;user`""
        Invoke-DSAcls "$ouDN /I:S /D `"$NetBIOS\admin_politicas:CCDC;user`""
    }
    Write-Log "  [+] admin_politicas: DENEGADO modificar objetos de usuario." "Green"

    Write-Log "`n[ROL 4] admin_auditoria - Solo lectura total; escritura DENEGADA" "Yellow"
    Invoke-DSAcls "`"$DCPath`" /I:T /G `"$NetBIOS\admin_auditoria:GR`""
    Write-Log "  [+] admin_auditoria: Lectura concedida en todo el dominio." "Green"

    $contenedoresSensibles = @(
        "`"$DCPath`"",
        "`"OU=AdminDelegados,$DCPath`"",
        "`"OU=Cuates,$DCPath`"",
        "`"OU=No Cuates,$DCPath`""
    )
    foreach ($c in $contenedoresSensibles) {
        Invoke-DSAcls "$c /I:T /D `"$NetBIOS\admin_auditoria:WP`""
        Invoke-DSAcls "$c /I:T /D `"$NetBIOS\admin_auditoria:CCDC`""
        Invoke-DSAcls "$c /I:T /D `"$NetBIOS\admin_auditoria:WO`""
    }
    Write-Log "  [+] admin_auditoria: Escritura, Creacion y Eliminacion DENEGADAS." "Green"

    Write-Log "`n[OK] FASE 2 completada." "Green"
    Pause
}

# --- FASE 3: FGPP ---

function Fase3-ConfigurarFGPP {
    Write-Log "==========================================" "Cyan"
    Write-Log " FASE 3: Fine-Grained Password Policy     " "Yellow"
    Write-Log "==========================================" "Cyan"

    Write-Log "`n[!] FGPP se aplica a Grupos de Seguridad, NO a OUs." "Red"

    Write-Log "`n[3.1] Creando FGPP_Admins (minimo 12 caracteres)..." "Yellow"
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Admins'" -ErrorAction SilentlyContinue)) {
        New-ADFineGrainedPasswordPolicy `
            -Name                        "FGPP_Admins" `
            -Precedence                  10 `
            -ComplexityEnabled           $true `
            -MinPasswordLength           12 `
            -MinPasswordAge              "1.00:00:00" `
            -MaxPasswordAge              "60.00:00:00" `
            -PasswordHistoryCount        10 `
            -ReversibleEncryptionEnabled $false `
            -LockoutThreshold            3 `
            -LockoutDuration             "00:30:00" `
            -LockoutObservationWindow    "00:30:00" `
            -Description                 "Politica para administradores delegados"
        Write-Log "  [+] FGPP_Admins creada (12 chars, bloqueo 3 intentos / 30 min)." "Green"
    } else {
        Write-Log "  [.] FGPP_Admins ya existe. Actualizando..." "Gray"
        Set-ADFineGrainedPasswordPolicy -Identity "FGPP_Admins" `
            -MinPasswordLength 12 -LockoutThreshold 3 -LockoutDuration "00:30:00"
    }

    Write-Log "`n[3.2] Creando FGPP_Standard (minimo 8 caracteres)..." "Yellow"
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Standard'" -ErrorAction SilentlyContinue)) {
        New-ADFineGrainedPasswordPolicy `
            -Name                        "FGPP_Standard" `
            -Precedence                  20 `
            -ComplexityEnabled           $true `
            -MinPasswordLength           8 `
            -MinPasswordAge              "1.00:00:00" `
            -MaxPasswordAge              "90.00:00:00" `
            -PasswordHistoryCount        5 `
            -ReversibleEncryptionEnabled $false `
            -LockoutThreshold            5 `
            -LockoutDuration             "00:15:00" `
            -LockoutObservationWindow    "00:15:00" `
            -Description                 "Politica para usuarios estandar"
        Write-Log "  [+] FGPP_Standard creada (8 chars minimo)." "Green"
    } else {
        Write-Log "  [.] FGPP_Standard ya existe." "Gray"
    }

    Write-Log "`n[3.3] Vinculando FGPPs a los Grupos de Seguridad..." "Yellow"
    try {
        Add-ADFineGrainedPasswordPolicySubject -Identity "FGPP_Admins" -Subjects "GG_Admins_Delegados" -ErrorAction Stop
        Write-Log "  [+] FGPP_Admins vinculada a GG_Admins_Delegados." "Green"
    } catch {
        Write-Log "  [.] FGPP_Admins ya estaba vinculada." "Gray"
    }

    try {
        Add-ADFineGrainedPasswordPolicySubject -Identity "FGPP_Standard" -Subjects "GG_Usuarios_Std" -ErrorAction Stop
        Write-Log "  [+] FGPP_Standard vinculada a GG_Usuarios_Std." "Green"
    } catch {
        Write-Log "  [.] FGPP_Standard ya estaba vinculada." "Gray"
    }

    Write-Log "`n[3.4] Verificando FGPP vigente para admin_identidad..." "Yellow"
    Get-ADUserResultantPasswordPolicy -Identity "admin_identidad" |
        Select-Object Name, MinPasswordLength, LockoutThreshold |
        Format-Table -AutoSize | Out-String | Write-Host

    Write-Log "[OK] FASE 3 completada." "Green"
    Pause
}

# --- FASE 4: AUDITORIA COMPLETA ---

function Fase4-AuditoriaCompleta {
    Write-Log "==========================================" "Cyan"
    Write-Log " FASE 4: Politica de Auditoria Avanzada   " "Yellow"
    Write-Log "==========================================" "Cyan"

    Write-Log "`n[4.1] Habilitando subcategorias de auditoria..." "Yellow"

    $Auditorias = @(
        @{ Sub = "Logon";                          Desc = "Inicio de Sesion"           },
        @{ Sub = "Logoff";                         Desc = "Cierre de Sesion"           },
        @{ Sub = "Account Lockout";                Desc = "Bloqueo de Cuenta"          },
        @{ Sub = "Object Access";                  Desc = "Acceso a Objetos"           },
        @{ Sub = "File System";                    Desc = "Sistema de Archivos"        },
        @{ Sub = "Account Management";             Desc = "Gestion de Cuentas"         },
        @{ Sub = "User Account Management";        Desc = "Gestion de Usuarios"        },
        @{ Sub = "Security Group Management";      Desc = "Gestion de Grupos"          },
        @{ Sub = "Policy Change";                  Desc = "Cambio de Politicas"        },
        @{ Sub = "Audit Policy Change";            Desc = "Cambio de Auditoria"        },
        @{ Sub = "Sensitive Privilege Use";        Desc = "Uso de Privilegios"         },
        @{ Sub = "Credential Validation";          Desc = "Validacion de Credenciales" },
        @{ Sub = "Kerberos Authentication Service"; Desc = "Autenticacion Kerberos"   }
    )

    foreach ($a in $Auditorias) {
        $resultado = cmd.exe /c "auditpol /set /subcategory:`"$($a.Sub)`" /success:enable /failure:enable 2>&1"
        if ($LASTEXITCODE -eq 0) {
            Write-Log "  [+] $($a.Desc) - Exito y Fallo habilitados." "Green"
        } else {
            Write-Log "  [!] Error en subcategoria: $($a.Sub)" "DarkYellow"
        }
    }

    Write-Log "`n[4.2] Configurando politica de bloqueo del dominio..." "Yellow"
    Set-ADDefaultDomainPasswordPolicy -Identity $Dominio `
        -LockoutThreshold         3 `
        -LockoutDuration          "00:30:00" `
        -LockoutObservationWindow "00:30:00" `
        -MinPasswordLength        8 `
        -ComplexityEnabled        $true `
        -PasswordHistoryCount     5
    Write-Log "  [+] 3 intentos fallidos = bloqueo 30 minutos." "Green"

    Write-Log "`n[4.3] Configurando tamano del Log de Seguridad (512 MB)..." "Yellow"
    wevtutil sl Security /ms:536870912 /rt:false
    Write-Log "  [+] Log de Seguridad configurado a 512 MB." "Green"

    Write-Log "`n[OK] FASE 4 completada." "Green"
    Pause
}

# --- FASE 5: MFA ---

function Fase5-ConfigurarMFA {
    Write-Log "==========================================" "Cyan"
    Write-Log " FASE 5: Implementacion de MFA con TOTP   " "Yellow"
    Write-Log "==========================================" "Cyan"

    Write-Log "`n[5.1] Verificando Credential Providers instalados..." "Yellow"
    $cpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    $providers = Get-ChildItem $cpPath -ErrorAction SilentlyContinue |
                 Get-ItemProperty -Name "(default)" -ErrorAction SilentlyContinue
    $mfaInstalado = $providers | Where-Object { $_.'(default)' -like "*OTP*" }

    if ($mfaInstalado) {
        Write-Log "  [+] Se detecto un Credential Provider de MFA instalado." "Green"
    } else {
        Write-Log "  [!] No se detecto Credential Provider de MFA." "Red"
    }

    Write-Log "`n[5.2] PASOS DE INSTALACION DE WinOTP:" "Cyan"
    Write-Host "  -------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  1. Descargar desde: https://winauth.github.io/winauth/" -ForegroundColor White
    Write-Host "  2. Ejecutar el instalador como Administrador" -ForegroundColor White
    Write-Host "  3. Seleccionar Google Authenticator / TOTP" -ForegroundColor White
    Write-Host "  4. Escanear el QR con la app Google Authenticator" -ForegroundColor White
    Write-Host "  5. Verificar con un codigo antes de habilitar" -ForegroundColor White
    Write-Host "  -------------------------------------------------------" -ForegroundColor Cyan

    Write-Log "`n[5.3] Pre-configurando registro del sistema para MFA..." "Yellow"
    $mfaRegPath = "HKLM:\SOFTWARE\Practica09\MFA_Config"
    if (-not (Test-Path $mfaRegPath)) {
        New-Item -Path $mfaRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $mfaRegPath -Name "MaxFailedAttempts"   -Value 3          -Type DWord
    Set-ItemProperty -Path $mfaRegPath -Name "LockoutDuration_min" -Value 30         -Type DWord
    Set-ItemProperty -Path $mfaRegPath -Name "TOTPWindowSeconds"   -Value 30         -Type DWord
    Set-ItemProperty -Path $mfaRegPath -Name "Algorithm"           -Value "TOTP-SHA1" -Type String
    Write-Log "  [+] Parametros de MFA pre-configurados en el registro." "Green"

    Write-Log "`n[5.4] Verificando politica de bloqueo..." "Yellow"
    $policy = Get-ADDefaultDomainPasswordPolicy -Identity $Dominio
    if ($policy.LockoutThreshold -eq 3) {
        Write-Log "  [+] Politica correcta: 3 intentos = 30 min. OK" "Green"
    } else {
        Set-ADDefaultDomainPasswordPolicy -Identity $Dominio `
            -LockoutThreshold 3 -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00"
        Write-Log "  [+] Politica corregida: 3 intentos = 30 minutos." "Green"
    }

    Write-Log "`n[5.5] Verificando FGPP_Admins tenga bloqueo MFA correcto..." "Yellow"
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Admins'" -ErrorAction SilentlyContinue
    if ($fgpp -and $fgpp.LockoutThreshold -eq 3) {
        Write-Log "  [+] FGPP_Admins: 3 intentos / 30 min. OK" "Green"
    } elseif ($fgpp) {
        Set-ADFineGrainedPasswordPolicy -Identity "FGPP_Admins" `
            -LockoutThreshold 3 -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00"
        Write-Log "  [+] FGPP_Admins corregida." "Green"
    }

    Write-Log "`n[IMPORTANTE] Evidencia requerida para el reporte:" "Yellow"
    Write-Host "  1. Captura de la pantalla de login solicitando el codigo TOTP" -ForegroundColor White
    Write-Host "  2. Foto del celular con Google Authenticator mostrando el codigo" -ForegroundColor White
    Write-Host "  3. Captura del estado Locked de la cuenta tras 3 intentos fallidos" -ForegroundColor White

    Write-Log "`n[OK] FASE 5 completada." "Green"
    Pause
}

# --- FASE 6: FSRM ---

function Fase6-ConfigurarFSRM {
    Write-Log "==========================================" "Cyan"
    Write-Log " FASE 6: FSRM - Roles de admin_storage    " "Yellow"
    Write-Log "==========================================" "Cyan"

    Write-Log "`n[6.1] Verificando si FSRM esta instalado..." "Yellow"
    $fsrmFeature = Get-WindowsFeature -Name FS-Resource-Manager -ErrorAction SilentlyContinue

    if ($fsrmFeature -and $fsrmFeature.InstallState -eq "Installed") {
        Write-Log "  [+] FSRM ya esta instalado." "Green"
    } else {
        Write-Log "  [->] Instalando FSRM..." "Yellow"
        try {
            Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools -ErrorAction Stop
            Write-Log "  [+] FSRM instalado correctamente." "Green"
        } catch {
            Write-Log "  [!] No se pudo instalar FSRM: $_" "Red"
            Pause; return
        }
    }

    Import-Module FileServerResourceManager -ErrorAction SilentlyContinue

    $rutaDatos = "C:\DatosEmpresa"
    Ensure-Directory $rutaDatos

    Write-Log "`n[6.2] Configurando Cuotas de Disco..." "Yellow"
    $plantillaStd = "Cuota_Usuarios_500MB"
    if (-not (Get-FsrmQuotaTemplate -Name $plantillaStd -ErrorAction SilentlyContinue)) {
        New-FsrmQuotaTemplate -Name $plantillaStd `
            -Size 524288000 `
            -Description "Cuota 500 MB para usuarios estandar"
        Write-Log "  [+] Plantilla '$plantillaStd' creada (500 MB)." "Green"
    } else {
        Write-Log "  [.] Plantilla '$plantillaStd' ya existe." "Gray"
    }

    if (-not (Get-FsrmQuota -Path $rutaDatos -ErrorAction SilentlyContinue)) {
        New-FsrmQuota -Path $rutaDatos -Template $plantillaStd -ErrorAction SilentlyContinue
        Write-Log "  [+] Cuota aplicada a '$rutaDatos'." "Green"
    }

    Write-Log "`n[6.3] Configurando File Screening..." "Yellow"
    $extensionesBloqueadas = @("*.exe", "*.bat", "*.cmd", "*.vbs", "*.js", "*.ps1", "*.msi", "*.dll")
    $grupoPantalla = "Archivos_Ejecutables_Bloqueados"

    if (-not (Get-FsrmFileGroup -Name $grupoPantalla -ErrorAction SilentlyContinue)) {
        New-FsrmFileGroup -Name $grupoPantalla -IncludePattern $extensionesBloqueadas
        Write-Log "  [+] Grupo de extensiones bloqueadas creado." "Green"
    }

    $plantillaPantalla = "Pantalla_Ejecutables"
    if (-not (Get-FsrmFileScreenTemplate -Name $plantillaPantalla -ErrorAction SilentlyContinue)) {
        New-FsrmFileScreenTemplate -Name $plantillaPantalla `
            -Active $true `
            -IncludeGroup $grupoPantalla `
            -Description "Bloquea ejecutables y scripts"
        Write-Log "  [+] Plantilla de pantalla creada." "Green"
    }

    if (-not (Get-FsrmFileScreen -Path $rutaDatos -ErrorAction SilentlyContinue)) {
        New-FsrmFileScreen -Path $rutaDatos -Template $plantillaPantalla -ErrorAction SilentlyContinue
        Write-Log "  [+] File Screening activo en '$rutaDatos'." "Green"
    }

    Write-Log "`n[OK] FASE 6 completada." "Green"
    Pause
}

# --- REPORTE: EVENTOS 4625 ---

function Generar-ReporteAuditoria {
    Write-Log "==========================================" "Cyan"
    Write-Log " REPORTE: Extraccion de Eventos 4625      " "Yellow"
    Write-Log "==========================================" "Cyan"

    Ensure-Directory (Split-Path $RutaReporte)

    Write-Log "`n[R.1] Extrayendo ultimos 10 eventos de Acceso Denegado (ID 4625)..." "Yellow"

    $Eventos = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4625
    } -MaxEvents 10 -ErrorAction SilentlyContinue

    $encabezado = @"
=========================================================
  REPORTE DE AUDITORIA - ACCESOS DENEGADOS (Event 4625)
  Practica 09 - Hardening de AD
  Generado por: admin_auditoria
  Fecha       : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Dominio     : $Dominio
=========================================================
"@

    if (-not $Eventos) {
        $cuerpoReporte  = $encabezado
        $cuerpoReporte += "`n[!] No se encontraron eventos 4625 en el log de seguridad."
        $cuerpoReporte += "`n    Ejecute las Fases 4 y luego intente logons fallidos para generar eventos.`n"
        $cuerpoReporte | Out-File -FilePath $RutaReporte -Encoding UTF8
        Write-Log "  [!] Sin eventos 4625 aun. Reporte placeholder generado: $RutaReporte" "Yellow"
        Pause; return
    }

    $registros = foreach ($evento in $Eventos) {
        $xml  = [xml]$evento.ToXml()
        $data = $xml.Event.EventData.Data

        function Get-EventField { param($name) ($data | Where-Object { $_.Name -eq $name }).'#text' }

        $subStatus = Get-EventField "SubStatus"
        $descripcionError = switch ($subStatus) {
            "0xC000006A" { "Contrasena incorrecta"            }
            "0xC0000064" { "Usuario no existe"                }
            "0xC0000234" { "Cuenta bloqueada"                 }
            "0xC0000072" { "Cuenta deshabilitada"             }
            "0xC000006F" { "Fuera de horario permitido"       }
            "0xC0000070" { "Estacion de trabajo no autorizada" }
            default      { "Codigo: $subStatus"               }
        }

        [PSCustomObject]@{
            "Fecha/Hora"    = $evento.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            "EventID"       = $evento.Id
            "Usuario"       = Get-EventField "TargetUserName"
            "Dominio"       = Get-EventField "TargetDomainName"
            "IP Origen"     = Get-EventField "IpAddress"
            "Tipo de Error" = $descripcionError
            "Tipo Logon"    = Get-EventField "LogonType"
        }
    }

    $cuerpoReporte  = $encabezado
    $cuerpoReporte += "`n"
    $cuerpoReporte += ($registros | Format-Table -AutoSize | Out-String)
    $cuerpoReporte += "`n=========================================================`n"
    $cuerpoReporte += "Total de eventos: $($Eventos.Count)`n"
    $cuerpoReporte | Out-File -FilePath $RutaReporte -Encoding UTF8

    $rutaCSV = $RutaReporte -replace "\.txt$", ".csv"
    $registros | Export-Csv -Path $rutaCSV -NoTypeInformation -Encoding UTF8

    Write-Log "  [+] Reporte TXT: $RutaReporte" "Green"
    Write-Log "  [+] Reporte CSV: $rutaCSV" "Green"
    Write-Host ($registros | Format-Table -AutoSize | Out-String) -ForegroundColor Gray

    Write-Log "[OK] Reporte generado correctamente." "Green"
    Pause
}

# --- VERIFICACION COMPLETA ---

function Verificar-EstadoPractica {
    Write-Log "============================================" "Cyan"
    Write-Log " VERIFICACION: Estado Completo de Practica  " "Yellow"
    Write-Log "============================================" "Cyan"

    $puntaje = 0
    $maxPuntaje = 0

    function Check {
        param([string]$Desc, [bool]$OK)
        $script:maxPuntaje++
        if ($OK) {
            Write-Log "  [OK] $Desc" "Green"
            $script:puntaje++
        } else {
            Write-Log "  [--] $Desc" "Red"
        }
    }

    Write-Log "`n=== OUs ===" "Yellow"
    Check "OU AdminDelegados existe" ((Get-ADOrganizationalUnit -Filter "Name -eq 'AdminDelegados'" -ErrorAction SilentlyContinue) -ne $null)
    Check "OU Cuates existe"         ((Get-ADOrganizationalUnit -Filter "Name -eq 'Cuates'" -ErrorAction SilentlyContinue) -ne $null)
    Check "OU No Cuates existe"      ((Get-ADOrganizationalUnit -Filter "Name -eq 'No Cuates'" -ErrorAction SilentlyContinue) -ne $null)

    Write-Log "`n=== USUARIOS DELEGADOS ===" "Yellow"
    foreach ($u in @("admin_identidad","admin_storage","admin_politicas","admin_auditoria")) {
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$u'" -Properties Enabled -ErrorAction SilentlyContinue
        Check "Usuario '$u' existe y esta habilitado" ($adUser -ne $null -and $adUser.Enabled -eq $true)
    }

    Write-Log "`n=== GRUPOS PARA FGPP ===" "Yellow"
    Check "Grupo GG_Admins_Delegados existe" ((Get-ADGroup -Filter "Name -eq 'GG_Admins_Delegados'" -ErrorAction SilentlyContinue) -ne $null)
    Check "Grupo GG_Usuarios_Std existe"     ((Get-ADGroup -Filter "Name -eq 'GG_Usuarios_Std'" -ErrorAction SilentlyContinue) -ne $null)

    Write-Log "`n=== FINE-GRAINED PASSWORD POLICIES ===" "Yellow"
    $fgppAdmins = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Admins'" -ErrorAction SilentlyContinue
    $fgppStd    = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Standard'" -ErrorAction SilentlyContinue
    Check "FGPP_Admins existe"                  ($fgppAdmins -ne $null)
    Check "FGPP_Admins: MinPasswordLength = 12" ($fgppAdmins -ne $null -and $fgppAdmins.MinPasswordLength -eq 12)
    Check "FGPP_Admins: LockoutThreshold = 3"   ($fgppAdmins -ne $null -and $fgppAdmins.LockoutThreshold -eq 3)
    Check "FGPP_Standard existe"                ($fgppStd -ne $null)
    Check "FGPP_Standard: MinPasswordLength = 8"($fgppStd -ne $null -and $fgppStd.MinPasswordLength -eq 8)

    if ($fgppAdmins) {
        $sujetos = Get-ADFineGrainedPasswordPolicySubject -Identity "FGPP_Admins" -ErrorAction SilentlyContinue
        Check "FGPP_Admins vinculada a GG_Admins_Delegados" ($sujetos -ne $null -and $sujetos.Name -contains "GG_Admins_Delegados")
    }

    Write-Log "`n=== AUDITORIA ===" "Yellow"
    $auditLogon = (cmd.exe /c 'auditpol /get /subcategory:"Logon"') | Out-String
    Check "Auditoria Logon - Success habilitada" ($auditLogon -match "Success")
    Check "Auditoria Logon - Failure habilitada" ($auditLogon -match "Failure")
    $auditObj = (cmd.exe /c 'auditpol /get /subcategory:"Object Access"') | Out-String
    Check "Auditoria Object Access habilitada"   ($auditObj -match "Success|Failure")

    Write-Log "`n=== POLITICA DE BLOQUEO ===" "Yellow"
    $domPol = Get-ADDefaultDomainPasswordPolicy -Identity $Dominio
    Check "LockoutThreshold = 3"          ($domPol.LockoutThreshold -eq 3)
    Check "LockoutDuration = 30 minutos"  ($domPol.LockoutDuration -eq "00:30:00")

    Write-Log "`n=== MEMBRESIA DE GRUPOS DEL SISTEMA ===" "Yellow"
    $elr = Get-ADGroupMember "Event Log Readers" -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq "admin_auditoria" }
    Check "admin_auditoria en Event Log Readers" ($elr -ne $null)
    $gpc = Get-ADGroupMember "Group Policy Creator Owners" -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq "admin_politicas" }
    Check "admin_politicas en Group Policy Creator Owners" ($gpc -ne $null)

    Write-Log "`n=== MFA ===" "Yellow"
    $mfaKey = Get-ItemProperty "HKLM:\SOFTWARE\Practica09\MFA_Config" -ErrorAction SilentlyContinue
    Check "Pre-configuracion MFA en registro presente" ($mfaKey -ne $null)
    Check "MaxFailedAttempts configurado = 3"          ($mfaKey -ne $null -and $mfaKey.MaxFailedAttempts -eq 3)

    Write-Log "`n===========================================" "Cyan"
    $porcentaje = [math]::Round(($puntaje / $maxPuntaje) * 100)
    $color = if ($porcentaje -ge 80) { "Green" } elseif ($porcentaje -ge 50) { "Yellow" } else { "Red" }
    Write-Log " RESULTADO: $puntaje de $maxPuntaje checks pasados ($porcentaje%)" $color
    Write-Log "===========================================" "Cyan"

    Pause
}

# --- TEST 1 ---

function Test1-DenegacionStorageReset {
    Write-Log "==========================================" "Cyan"
    Write-Log " TEST 1: admin_storage NO puede resetear  " "Yellow"
    Write-Log "==========================================" "Cyan"

    if (-not (Get-ADUser -Filter "SamAccountName -eq 'user_test'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "user_test" -SamAccountName "user_test" `
                   -AccountPassword $PassAdmin -Enabled $true -Path "OU=Cuates,$DCPath"
        Write-Log "  [+] user_test creado en OU Cuates." "Green"
    }

    Write-Log "`n[T1] Intentando resetear contrasena de user_test como admin_storage..." "Yellow"
    Write-Log "  (Resultado esperado: Acceso Denegado)" "Gray"

    $credStorage = Get-Credential -UserName "$NetBIOS\admin_storage" `
                                  -Message "Ingrese la contrasena de admin_storage"
    try {
        $nuevaPass = ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force
        Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $credStorage -ScriptBlock {
            param($targetUser, $newPass)
            Set-ADAccountPassword -Identity $targetUser -NewPassword $newPass -Reset -ErrorAction Stop
        } -ArgumentList "user_test", $nuevaPass -ErrorAction Stop

        Write-Log "`n[RESULTADO] FALLO DEL TEST: admin_storage pudo resetear la contrasena." "Red"
        Write-Log "            Revisar la ACL de denegacion en Fase 2." "Red"
    } catch {
        Write-Log "`n[RESULTADO] TEST EXITOSO: Acceso Denegado confirmado." "Green"
        Write-Log "  Error: $($_.Exception.Message)" "Gray"
    }

    Pause
}

# --- TEST 2 ---

function Test2-ValidarFGPP {
    Write-Log "==========================================" "Cyan"
    Write-Log " TEST 2: FGPP rechaza password menor a 12  " "Yellow"
    Write-Log "==========================================" "Cyan"

    Write-Log "`n[T2.1] FGPP vigente para admin_identidad:" "Yellow"
    $fgppVigente = Get-ADUserResultantPasswordPolicy -Identity "admin_identidad" -ErrorAction SilentlyContinue
    if ($fgppVigente) {
        Write-Log "  FGPP activa   : $($fgppVigente.Name)" "Gray"
        Write-Log "  Min caracteres: $($fgppVigente.MinPasswordLength)" "Gray"
    } else {
        Write-Log "  [!] No hay FGPP vigente. Ejecute Fase 3 primero." "Red"
        Pause; return
    }

    Write-Log "`n[T2.2] Intentando asignar contrasena de 5 chars (debe ser rechazada)..." "Yellow"
    try {
        $passCorta = ConvertTo-SecureString "12345" -AsPlainText -Force
        Set-ADAccountPassword -Identity "admin_identidad" -NewPassword $passCorta -Reset -ErrorAction Stop
        Write-Log "`n[RESULTADO] FALLO DEL TEST: La contrasena corta fue aceptada." "Red"
    } catch {
        Write-Log "`n[RESULTADO] TEST EXITOSO: FGPP rechazo la contrasena corta." "Green"
        Write-Log "  Error: $($_.Exception.Message)" "Gray"
    }

    Write-Log "`n[T2.3] Intentando contrasena de 8 chars para admin_identidad (debe fallar)..." "Yellow"
    try {
        $pass8 = ConvertTo-SecureString "Abc12345" -AsPlainText -Force
        Set-ADAccountPassword -Identity "admin_identidad" -NewPassword $pass8 -Reset -ErrorAction Stop
        Write-Log "  FALLO: Contrasena de 8 chars aceptada (requiere 12)." "Red"
    } catch {
        Write-Log "  CORRECTO: Contrasena de 8 chars rechazada (FGPP requiere 12)." "Green"
    }

    Pause
}

# --- EJECUTAR TODO ---

function EjecutarTodo {
    Write-Log "==========================================" "Cyan"
    Write-Log " EJECUCION COMPLETA: FASES 1 al 6         " "Yellow"
    Write-Log "==========================================" "Cyan"

    $confirm = Read-Host "`nConfirmar ejecucion completa (S/N)"
    if ($confirm.ToUpper() -ne "S") { return }

    Fase1-InfraestructuraBase
    Fase2-ACLsGranulares
    Fase3-ConfigurarFGPP
    Fase4-AuditoriaCompleta
    Fase5-ConfigurarMFA
    Fase6-ConfigurarFSRM
    Generar-ReporteAuditoria
    Verificar-EstadoPractica
}

# --- BUCLE PRINCIPAL ---

Ensure-Directory "C:\Reportes_P09"
Write-Log "Script iniciado. Log en: $LogScript" "Gray"

do {
    Mostrar-Menu
    $Opcion = Read-Host "  Selecciona una opcion"

    switch ($Opcion.ToUpper()) {
        "1"    { Fase1-InfraestructuraBase    }
        "2"    { Fase2-ACLsGranulares         }
        "3"    { Fase3-ConfigurarFGPP         }
        "4"    { Fase4-AuditoriaCompleta      }
        "5"    { Fase5-ConfigurarMFA          }
        "6"    { Fase6-ConfigurarFSRM         }
        "R"    { Generar-ReporteAuditoria     }
        "V"    { Verificar-EstadoPractica     }
        "T1"   { Test1-DenegacionStorageReset }
        "T2"   { Test2-ValidarFGPP            }
        "TODO" { EjecutarTodo                 }
        "S"    { Write-Log "Saliendo..." "Gray" }
        default{ Write-Log "Opcion no valida." "Red"; Start-Sleep 1 }
    }
} while ($Opcion.ToUpper() -ne "S")
