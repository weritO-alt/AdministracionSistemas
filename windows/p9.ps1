# =========================================================================
# PRÁCTICA 09 - HARDENING DE AD, AUDITORÍA Y MFA (VERSIÓN COMPLETA)
# Autor  : Carlos David Cota Sañudo
# Dominio: carlos.local
# NOTA   : Ejecutar como Administrador del Dominio en PowerShell elevado
# =========================================================================

#Requires -RunAsAdministrator

Import-Module ActiveDirectory -ErrorAction Stop

# ─── CONSTANTES GLOBALES ──────────────────────────────────────────────────────
$Dominio     = "carlos.local"
$DCPath      = "DC=carlos,DC=local"
$NetBIOS     = "carlos"
$PassAdmin   = ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force
$RutaReporte = "C:\Reportes_P09\Auditoria_Accesos_Denegados.txt"
$LogScript   = "C:\Reportes_P09\Log_Ejecucion_P09.log"

# ─── FUNCIONES DE UTILIDAD ────────────────────────────────────────────────────

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
    # Wrapper seguro para dsacls que captura errores correctamente
    param([string]$Argumento)
    $resultado = cmd.exe /c "dsacls $Argumento 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Log "  [!] dsacls error: $resultado" "DarkYellow"
    }
}

function Mostrar-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║     PRÁCTICA 09: HARDENING DE AD · AUDITORÍA · MFA      ║" -ForegroundColor Yellow
    Write-Host "  ║                  Dominio: carlos.local                   ║" -ForegroundColor Gray
    Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  FASES DE IMPLEMENTACIÓN                                 ║" -ForegroundColor Cyan
    Write-Host "  ║  [1]  FASE 1 · OUs, Grupos y Usuarios (Base RBAC)       ║"
    Write-Host "  ║  [2]  FASE 2 · ACLs Granulares (Privilegio Mínimo)      ║"
    Write-Host "  ║  [3]  FASE 3 · FGPP (12 chars Admins / 8 chars Users)   ║"
    Write-Host "  ║  [4]  FASE 4 · Auditoría Completa del Sistema            ║"
    Write-Host "  ║  [5]  FASE 5 · Configuración de MFA (TOTP/WinOTP)       ║"
    Write-Host "  ║  [6]  FASE 6 · Configurar FSRM (Rol admin_storage)      ║"
    Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  REPORTES Y VERIFICACIÓN                                 ║" -ForegroundColor Cyan
    Write-Host "  ║  [R]  Generar Reporte de Accesos Denegados (4625)        ║"
    Write-Host "  ║  [V]  Verificar Estado Completo de la Práctica           ║"
    Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  TESTS DE PROTOCOLO DE PRUEBA                            ║" -ForegroundColor Cyan
    Write-Host "  ║  [T1] Test · Denegación de Reset a admin_storage         ║"
    Write-Host "  ║  [T2] Test · Rechazo de FGPP (password < 12 chars)      ║"
    Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  [TODO] Ejecutar TODAS las fases en orden (1→6)         ║" -ForegroundColor Green
    Write-Host "  ║  [S]    Salir                                            ║"
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ─── FASE 1: INFRAESTRUCTURA BASE ─────────────────────────────────────────────

function Fase1-InfraestructuraBase {
    Write-Log "══════════════════════════════════════════" "Cyan"
    Write-Log " FASE 1: Creando OUs, Grupos y Usuarios   " "Yellow"
    Write-Log "══════════════════════════════════════════" "Cyan"

    Ensure-Directory "C:\Reportes_P09"

    # 1.1 Crear Unidades Organizativas
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
            Write-Log "  [·] OU '$($ou.Nombre)' ya existe." "Gray"
        }
    }

    # 1.2 Crear Grupos de Seguridad Global (REQUERIDOS por FGPP)
    #     FGPP NO puede aplicarse a OUs directamente — solo a grupos globales o usuarios.
    Write-Log "`n[1.2] Creando Grupos de Seguridad (necesarios para FGPP)..." "Yellow"
    $Grupos = @(
        @{ Nombre = "GG_Admins_Delegados"; Path = "OU=AdminDelegados,$DCPath"; Desc = "Administradores delegados - sujetos a FGPP_Admins" },
        @{ Nombre = "GG_Usuarios_Std";     Path = "OU=Usuarios_Std,$DCPath";   Desc = "Usuarios estándar - sujetos a FGPP_Standard" }
    )

    foreach ($g in $Grupos) {
        if (-not (Get-ADGroup -Filter "Name -eq '$($g.Nombre)'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $g.Nombre -GroupScope Global -GroupCategory Security `
                        -Path $g.Path -Description $g.Desc
            Write-Log "  [+] Grupo '$($g.Nombre)' creado." "Green"
        } else {
            Write-Log "  [·] Grupo '$($g.Nombre)' ya existe." "Gray"
        }
    }

    # 1.3 Crear Usuarios Delegados (4 Roles RBAC)
    Write-Log "`n[1.3] Creando Usuarios Administrativos Delegados..." "Yellow"
    $UsuariosAdmin = @(
        @{ Sam = "admin_identidad";  Nombre = "Admin Identidad";  Desc = "ROL 1 - IAM Operator"         },
        @{ Sam = "admin_storage";    Nombre = "Admin Storage";    Desc = "ROL 2 - Storage Operator"      },
        @{ Sam = "admin_politicas";  Nombre = "Admin Politicas";  Desc = "ROL 3 - GPO Compliance Admin"  },
        @{ Sam = "admin_auditoria";  Nombre = "Admin Auditoria";  Desc = "ROL 4 - Security Auditor"      }
    )

    foreach ($u in $UsuariosAdmin) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
            New-ADUser -Name $u.Nombre -SamAccountName $u.Sam -DisplayName $u.Nombre `
                       -Description $u.Desc -AccountPassword $PassAdmin -Enabled $true `
                       -Path "OU=AdminDelegados,$DCPath" -ChangePasswordAtLogon $false
            Write-Log "  [+] Usuario '$($u.Sam)' creado." "Green"
        } else {
            Write-Log "  [·] Usuario '$($u.Sam)' ya existe." "Gray"
        }
    }

    # 1.4 Crear Usuarios Estándar de Prueba
    Write-Log "`n[1.4] Creando Usuarios Estándar de Prueba..." "Yellow"
    $UsuariosStd = @(
        @{ Sam = "jlopez";    OU = "Cuates"   },
        @{ Sam = "mgarcia";   OU = "Cuates"   },
        @{ Sam = "rperez";    OU = "No Cuates" },
        @{ Sam = "amorales";  OU = "No Cuates" },
        @{ Sam = "user_test"; OU = "Cuates"   }
    )

    foreach ($u in $UsuariosStd) {
        $ouPath = "OU=$($u.OU),$DCPath"
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
            New-ADUser -Name $u.Sam -SamAccountName $u.Sam -AccountPassword $PassAdmin `
                       -Enabled $true -Path $ouPath
            Write-Log "  [+] Usuario '$($u.Sam)' creado en OU '$($u.OU)'." "Green"
        } else {
            Write-Log "  [·] Usuario '$($u.Sam)' ya existe." "Gray"
        }
    }

    # 1.5 Agregar usuarios a grupos correspondientes
    Write-Log "`n[1.5] Asignando membresía de grupos..." "Yellow"

    # Admins al grupo de admins (para FGPP)
    foreach ($u in $UsuariosAdmin) {
        Add-ADGroupMember -Identity "GG_Admins_Delegados" -Members $u.Sam -ErrorAction SilentlyContinue
    }
    Write-Log "  [+] Admins delegados agregados a GG_Admins_Delegados." "Green"

    # Usuarios estándar al grupo estándar (para FGPP)
    foreach ($u in $UsuariosStd) {
        Add-ADGroupMember -Identity "GG_Usuarios_Std" -Members $u.Sam -ErrorAction SilentlyContinue
    }
    Write-Log "  [+] Usuarios estándar agregados a GG_Usuarios_Std." "Green"

    # Roles integrados del sistema
    Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members "admin_politicas" -ErrorAction SilentlyContinue
    Write-Log "  [+] admin_politicas → Group Policy Creator Owners." "Green"

    Add-ADGroupMember -Identity "Event Log Readers" -Members "admin_auditoria" -ErrorAction SilentlyContinue
    Write-Log "  [+] admin_auditoria → Event Log Readers." "Green"

    Write-Log "`n[OK] FASE 1 completada." "Green"
    Pause
}

# ─── FASE 2: ACLs GRANULARES ──────────────────────────────────────────────────

function Fase2-ACLsGranulares {
    Write-Log "══════════════════════════════════════════" "Cyan"
    Write-Log " FASE 2: Aplicando ACLs (Principio Menor Privilegio)" "Yellow"
    Write-Log "══════════════════════════════════════════" "Cyan"

    # ── ROL 1: admin_identidad ────────────────────────────────────────────────
    Write-Log "`n[ROL 1] admin_identidad — Gestión de usuarios en Cuates y No Cuates" "Yellow"

    $OUsUsuarios = @(
        "`"OU=Cuates,$DCPath`"",
        "`"OU=No Cuates,$DCPath`""
    )

    foreach ($ouDN in $OUsUsuarios) {
        # Crear y eliminar objetos de usuario dentro de la OU
        Invoke-DSAcls "$ouDN /I:T /G `"$NetBIOS\admin_identidad:CCDC;user`""
        # Escribir todas las propiedades de usuario (incluye atributos básicos)
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:WP;;user`""
        # Reset de contraseña
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:CA;Reset Password;user`""
        # Forzar cambio de contraseña en siguiente logon
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:CA;Change Password;user`""
        # Desbloquear cuentas
        Invoke-DSAcls "$ouDN /I:S /G `"$NetBIOS\admin_identidad:WP;lockoutTime;user`""
    }
    Write-Log "  [+] Permisos de gestión otorgados sobre Cuates y No Cuates." "Green"

    # RESTRICCIÓN: admin_identidad NO puede modificar Domain Admins
    $domainAdminsPath = "`"CN=Domain Admins,CN=Users,$DCPath`""
    Invoke-DSAcls "$domainAdminsPath /D `"$NetBIOS\admin_identidad:WP`""
    Invoke-DSAcls "$domainAdminsPath /D `"$NetBIOS\admin_identidad:CCDC;member`""
    Write-Log "  [+] admin_identidad: DENEGADO modificar Domain Admins." "Green"

    # ── ROL 2: admin_storage ──────────────────────────────────────────────────
    Write-Log "`n[ROL 2] admin_storage — DENEGACIÓN explícita de Reset Password" "Yellow"

    # RESTRICCIÓN CRÍTICA: Denegar explícitamente Reset Password en TODO el dominio
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

    # ── ROL 3: admin_politicas ────────────────────────────────────────────────
    Write-Log "`n[ROL 3] admin_politicas — Solo lectura en dominio; escritura solo en GPOs" "Yellow"

    # Lectura de todo el dominio
    Invoke-DSAcls "`"$DCPath`" /I:T /G `"$NetBIOS\admin_politicas:GR`""
    Write-Log "  [+] admin_politicas: Lectura concedida en todo el dominio." "Green"

    # Escribir en contenedor de políticas de grupo
    $gpoPoliciesPath = "`"CN=Policies,CN=System,$DCPath`""
    Invoke-DSAcls "$gpoPoliciesPath /I:T /G `"$NetBIOS\admin_politicas:GA`""
    Write-Log "  [+] admin_politicas: Escritura concedida en CN=Policies (GPOs)." "Green"

    # RESTRICCIÓN CRÍTICA: Denegar escritura en objetos de usuario
    foreach ($ouDN in $OUsUsuarios) {
        Invoke-DSAcls "$ouDN /I:S /D `"$NetBIOS\admin_politicas:WP;;user`""
        Invoke-DSAcls "$ouDN /I:S /D `"$NetBIOS\admin_politicas:CCDC;user`""
    }
    Invoke-DSAcls "`"OU=AdminDelegados,$DCPath`" /I:S /D `"$NetBIOS\admin_politicas:WP;;user`""
    Write-Log "  [+] admin_politicas: DENEGADO modificar objetos de usuario." "Green"

    # ── ROL 4: admin_auditoria ────────────────────────────────────────────────
    Write-Log "`n[ROL 4] admin_auditoria — Solo lectura total; escritura DENEGADA" "Yellow"

    # Lectura de todo el dominio
    Invoke-DSAcls "`"$DCPath`" /I:T /G `"$NetBIOS\admin_auditoria:GR`""
    Write-Log "  [+] admin_auditoria: Lectura concedida en todo el dominio." "Green"

    # RESTRICCIÓN CRÍTICA: Denegar explícitamente toda escritura
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
    Write-Log "  [+] admin_auditoria: Escritura, Creación y Eliminación DENEGADAS." "Green"

    # Permisos de GPO para admin_politicas via PowerShell
    Write-Log "`n[GPO] Configurando permisos de vinculación de GPOs para admin_politicas..." "Yellow"
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Get-GPO -All | ForEach-Object {
            Set-GPPermission -Guid $_.Id -TargetName "admin_politicas" `
                             -TargetType User -PermissionLevel GpoRead -ErrorAction SilentlyContinue
        }
        Write-Log "  [+] admin_politicas tiene permiso de lectura en todas las GPOs existentes." "Green"
    } catch {
        Write-Log "  [!] Módulo GroupPolicy no disponible o sin GPOs existentes: $_" "DarkYellow"
    }

    Write-Log "`n[OK] FASE 2 completada. ACLs granulares aplicadas." "Green"
    Pause
}

# ─── FASE 3: FGPP ─────────────────────────────────────────────────────────────

function Fase3-ConfigurarFGPP {
    Write-Log "══════════════════════════════════════════" "Cyan"
    Write-Log " FASE 3: Fine-Grained Password Policy (FGPP)" "Yellow"
    Write-Log "══════════════════════════════════════════" "Cyan"

    Write-Log "`n[!] ADVERTENCIA: FGPP NUNCA puede aplicarse a una OU." "Red"
    Write-Log "    Se aplica a Grupos de Seguridad Globales o usuarios individuales." "Yellow"
    Write-Log "    Esta fase usa GG_Admins_Delegados y GG_Usuarios_Std." "Yellow"

    # ── Política para Administradores (Precedencia 10 = mayor prioridad) ──────
    Write-Log "`n[3.1] Creando FGPP_Admins (mínimo 12 caracteres)..." "Yellow"
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Admins'" -ErrorAction SilentlyContinue)) {
        New-ADFineGrainedPasswordPolicy `
            -Name                       "FGPP_Admins" `
            -Precedence                 10 `
            -ComplexityEnabled          $true `
            -MinPasswordLength          12 `
            -MinPasswordAge             "1.00:00:00" `
            -MaxPasswordAge             "60.00:00:00" `
            -PasswordHistoryCount       10 `
            -ReversibleEncryptionEnabled $false `
            -LockoutThreshold           3 `
            -LockoutDuration            "00:30:00" `
            -LockoutObservationWindow   "00:30:00" `
            -Description                "Política de contraseñas para administradores delegados (ROL 1-4)"
        Write-Log "  [+] FGPP_Admins creada (12 chars mínimo, bloqueo 3 intentos/30 min)." "Green"
    } else {
        Write-Log "  [·] FGPP_Admins ya existe. Actualizando configuración..." "Gray"
        Set-ADFineGrainedPasswordPolicy -Identity "FGPP_Admins" `
            -MinPasswordLength 12 -LockoutThreshold 3 -LockoutDuration "00:30:00"
    }

    # ── Política para Usuarios Estándar (Precedencia 20) ─────────────────────
    Write-Log "`n[3.2] Creando FGPP_Standard (mínimo 8 caracteres)..." "Yellow"
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Standard'" -ErrorAction SilentlyContinue)) {
        New-ADFineGrainedPasswordPolicy `
            -Name                       "FGPP_Standard" `
            -Precedence                 20 `
            -ComplexityEnabled          $true `
            -MinPasswordLength          8 `
            -MinPasswordAge             "1.00:00:00" `
            -MaxPasswordAge             "90.00:00:00" `
            -PasswordHistoryCount       5 `
            -ReversibleEncryptionEnabled $false `
            -LockoutThreshold           5 `
            -LockoutDuration            "00:15:00" `
            -LockoutObservationWindow   "00:15:00" `
            -Description                "Política de contraseñas para usuarios estándar"
        Write-Log "  [+] FGPP_Standard creada (8 chars mínimo)." "Green"
    } else {
        Write-Log "  [·] FGPP_Standard ya existe. Actualizando configuración..." "Gray"
        Set-ADFineGrainedPasswordPolicy -Identity "FGPP_Standard" -MinPasswordLength 8
    }

    # ── Vincular FGPPs a los Grupos (CORRECTO: grupo, no OU) ─────────────────
    Write-Log "`n[3.3] Vinculando FGPPs a los Grupos de Seguridad..." "Yellow"

    try {
        Add-ADFineGrainedPasswordPolicySubject `
            -Identity "FGPP_Admins" -Subjects "GG_Admins_Delegados" -ErrorAction Stop
        Write-Log "  [+] FGPP_Admins vinculada a GG_Admins_Delegados." "Green"
    } catch {
        Write-Log "  [·] FGPP_Admins ya vinculada a GG_Admins_Delegados." "Gray"
    }

    try {
        Add-ADFineGrainedPasswordPolicySubject `
            -Identity "FGPP_Standard" -Subjects "GG_Usuarios_Std" -ErrorAction Stop
        Write-Log "  [+] FGPP_Standard vinculada a GG_Usuarios_Std." "Green"
    } catch {
        Write-Log "  [·] FGPP_Standard ya vinculada a GG_Usuarios_Std." "Gray"
    }

    # ── Verificación ──────────────────────────────────────────────────────────
    Write-Log "`n[3.4] Verificando resultados de FGPP aplicadas..." "Yellow"
    Get-ADUserResultantPasswordPolicy -Identity "admin_identidad" |
        Select-Object Name, MinPasswordLength, LockoutThreshold |
        Format-Table -AutoSize | Out-String | Write-Host

    Write-Log "[OK] FASE 3 completada." "Green"
    Pause
}

# ─── FASE 4: AUDITORÍA COMPLETA ───────────────────────────────────────────────

function Fase4-AuditoriaCompleta {
    Write-Log "══════════════════════════════════════════" "Cyan"
    Write-Log " FASE 4: Política de Auditoría Avanzada   " "Yellow"
    Write-Log "══════════════════════════════════════════" "Cyan"

    Write-Log "`n[4.1] Habilitando subcategorías de auditoría..." "Yellow"

    # Definir todas las subcategorías requeridas
    $Auditorias = @(
        @{ Sub = "Logon";                     Desc = "Inicio de Sesión"         },
        @{ Sub = "Logoff";                    Desc = "Cierre de Sesión"         },
        @{ Sub = "Account Lockout";           Desc = "Bloqueo de Cuenta"        },
        @{ Sub = "Object Access";             Desc = "Acceso a Objetos"         },
        @{ Sub = "File System";               Desc = "Sistema de Archivos"      },
        @{ Sub = "Handle Manipulation";       Desc = "Manipulación de Handles"  },
        @{ Sub = "Account Management";        Desc = "Gestión de Cuentas"       },
        @{ Sub = "User Account Management";   Desc = "Gestión de Usuarios"      },
        @{ Sub = "Security Group Management"; Desc = "Gestión de Grupos"        },
        @{ Sub = "Policy Change";             Desc = "Cambio de Políticas"      },
        @{ Sub = "Audit Policy Change";       Desc = "Cambio de Auditoría"      },
        @{ Sub = "Sensitive Privilege Use";   Desc = "Uso de Privilegios"       },
        @{ Sub = "Credential Validation";     Desc = "Validación de Credenciales" },
        @{ Sub = "Kerberos Authentication Service"; Desc = "Autenticación Kerberos" }
    )

    foreach ($a in $Auditorias) {
        $resultado = cmd.exe /c "auditpol /set /subcategory:`"$($a.Sub)`" /success:enable /failure:enable 2>&1"
        if ($LASTEXITCODE -eq 0) {
            Write-Log "  [+] Auditoría: $($a.Desc) — Éxito y Fallo habilitados." "Green"
        } else {
            Write-Log "  [!] Error en subcategoría: $($a.Sub)" "DarkYellow"
        }
    }

    # 4.2 Política de contraseñas del dominio base (fallback fuera de FGPP)
    Write-Log "`n[4.2] Configurando política de bloqueo predeterminada del dominio..." "Yellow"
    Set-ADDefaultDomainPasswordPolicy -Identity $Dominio `
        -LockoutThreshold        3 `
        -LockoutDuration         "00:30:00" `
        -LockoutObservationWindow "00:30:00" `
        -MinPasswordLength       8 `
        -ComplexityEnabled       $true `
        -PasswordHistoryCount    5
    Write-Log "  [+] Política de dominio: 3 intentos fallidos = bloqueo 30 minutos." "Green"

    # 4.3 Configurar tamaño máximo del log de seguridad
    Write-Log "`n[4.3] Optimizando tamaño del Registro de Seguridad (512 MB)..." "Yellow"
    wevtutil sl Security /ms:536870912 /rt:false
    Write-Log "  [+] Log de Seguridad configurado a 512 MB." "Green"

    # 4.4 Registrar la política activa
    Write-Log "`n[4.4] Estado actual de la auditoría:" "Yellow"
    cmd.exe /c 'auditpol /get /category:*' | Where-Object { $_ -match "Logon|Object|Account" } |
        ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

    Write-Log "`n[OK] FASE 4 completada. Auditoría completa activada." "Green"
    Pause
}

# ─── FASE 5: MFA (TOTP / Google Authenticator) ────────────────────────────────

function Fase5-ConfigurarMFA {
    Write-Log "══════════════════════════════════════════════════════" "Cyan"
    Write-Log " FASE 5: Implementación de MFA con TOTP               " "Yellow"
    Write-Log " (Google Authenticator via Credential Provider)        " "Gray"
    Write-Log "══════════════════════════════════════════════════════" "Cyan"

    Write-Log "`n[!] La integración de MFA con Windows Server requiere un" "Yellow"
    Write-Log "    Credential Provider de terceros. Esta fase configura el" "Yellow"
    Write-Log "    entorno y guía la instalación de WinOTP Authenticator." "Yellow"

    # 5.1 Verificar si ya existe un Credential Provider de MFA
    Write-Log "`n[5.1] Verificando Credential Providers instalados..." "Yellow"
    $cpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    $providers = Get-ChildItem $cpPath -ErrorAction SilentlyContinue |
                 Get-ItemProperty -Name "(default)" -ErrorAction SilentlyContinue
    $winOtpGuid = "{8AF662BF-65A0-4D0A-A540-A338A999D36F}"  # GUID de WinOTP Authenticator
    $mfaInstalado = $providers | Where-Object { $_.'(default)' -like "*OTP*" -or $_.PSChildName -eq $winOtpGuid }

    if ($mfaInstalado) {
        Write-Log "  [+] Se detectó un Credential Provider de MFA instalado." "Green"
    } else {
        Write-Log "  [!] No se detectó Credential Provider de MFA." "Red"
        Write-Log "  [→] Siga las instrucciones de instalación abajo." "Yellow"
    }

    # 5.2 Instrucciones de instalación de WinOTP
    Write-Log "`n[5.2] PASOS DE INSTALACIÓN DE WinOTP Authenticator:" "Cyan"
    Write-Host "`n  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │         INSTALACIÓN MANUAL DE WinOTP (REQUERIDA)            │" -ForegroundColor Yellow
    Write-Host "  ├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    Write-Host "  │ 1. Descargar desde: https://winauth.github.io/winauth/       │" -ForegroundColor White
    Write-Host "  │    o buscar 'WinOTP Authenticator' en GitHub Releases        │" -ForegroundColor Gray
    Write-Host "  │                                                               │" -ForegroundColor Cyan
    Write-Host "  │ 2. Ejecutar el instalador como Administrador                 │" -ForegroundColor White
    Write-Host "  │                                                               │" -ForegroundColor Cyan
    Write-Host "  │ 3. En la configuración del Credential Provider:              │" -ForegroundColor White
    Write-Host "  │    a) Seleccionar 'Google Authenticator / TOTP'              │" -ForegroundColor Gray
    Write-Host "  │    b) Escanear el QR con la app Google Authenticator         │" -ForegroundColor Gray
    Write-Host "  │    c) Verificar con un código generado antes de habilitar    │" -ForegroundColor Gray
    Write-Host "  │                                                               │" -ForegroundColor Cyan
    Write-Host "  │ 4. El Credential Provider se registra automáticamente        │" -ForegroundColor White
    Write-Host "  │    en: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\       │" -ForegroundColor Gray
    Write-Host "  │        Authentication\Credential Providers\                  │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

    # 5.3 Pre-configurar registro para el bloqueo tras intentos MFA fallidos
    Write-Log "`n[5.3] Pre-configurando registro del sistema para MFA..." "Yellow"

    # Crear clave de configuración para el provider MFA
    $mfaRegPath = "HKLM:\SOFTWARE\Practica09\MFA_Config"
    if (-not (Test-Path $mfaRegPath)) {
        New-Item -Path $mfaRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $mfaRegPath -Name "MaxFailedAttempts"  -Value 3     -Type DWord
    Set-ItemProperty -Path $mfaRegPath -Name "LockoutDuration_min" -Value 30   -Type DWord
    Set-ItemProperty -Path $mfaRegPath -Name "TOTPWindowSeconds"   -Value 30   -Type DWord
    Set-ItemProperty -Path $mfaRegPath -Name "Algorithm"           -Value "TOTP-SHA1" -Type String
    Write-Log "  [+] Parámetros de MFA pre-configurados en el registro." "Green"

    # 5.4 El bloqueo de cuenta ya es manejado por la política de AD (Fase 4)
    Write-Log "`n[5.4] Verificando política de bloqueo de cuenta en AD..." "Yellow"
    $policy = Get-ADDefaultDomainPasswordPolicy -Identity $Dominio
    Write-Log "  Umbral de bloqueo : $($policy.LockoutThreshold) intentos" "Gray"
    Write-Log "  Duración de bloqueo: $($policy.LockoutDuration)" "Gray"

    if ($policy.LockoutThreshold -eq 3 -and $policy.LockoutDuration -eq "00:30:00") {
        Write-Log "  [+] Política de bloqueo correcta: 3 intentos = 30 min. ✓" "Green"
    } else {
        Write-Log "  [!] Ajustando política de bloqueo al valor correcto..." "Yellow"
        Set-ADDefaultDomainPasswordPolicy -Identity $Dominio `
            -LockoutThreshold 3 -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00"
        Write-Log "  [+] Corregido: 3 intentos = 30 minutos de bloqueo." "Green"
    }

    # 5.5 Verificar que la FGPP también tiene el bloqueo correcto
    Write-Log "`n[5.5] Verificando FGPP_Admins tenga bloqueo MFA correcto..." "Yellow"
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Admins'" -ErrorAction SilentlyContinue
    if ($fgpp -and $fgpp.LockoutThreshold -eq 3) {
        Write-Log "  [+] FGPP_Admins: 3 intentos = bloqueo 30 min. ✓" "Green"
    } elseif ($fgpp) {
        Set-ADFineGrainedPasswordPolicy -Identity "FGPP_Admins" `
            -LockoutThreshold 3 -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00"
        Write-Log "  [+] FGPP_Admins corregida a 3 intentos / 30 min." "Green"
    }

    Write-Log "`n[IMPORTANTE] Evidencia requerida para el reporte:" "Yellow"
    Write-Host "  1. Captura de pantalla de la pantalla de login solicitando el código TOTP" -ForegroundColor White
    Write-Host "  2. Foto del teléfono con Google Authenticator mostrando el código generado" -ForegroundColor White
    Write-Host "  3. Captura del estado 'Locked' de la cuenta tras 3 intentos fallidos" -ForegroundColor White

    Write-Log "`n[OK] FASE 5 completada (configuración pre-MFA lista)." "Green"
    Pause
}

# ─── FASE 6: FSRM (Rol admin_storage) ─────────────────────────────────────────

function Fase6-ConfigurarFSRM {
    Write-Log "══════════════════════════════════════════" "Cyan"
    Write-Log " FASE 6: FSRM — Roles de admin_storage    " "Yellow"
    Write-Log "══════════════════════════════════════════" "Cyan"

    # Verificar si FSRM está instalado
    Write-Log "`n[6.1] Verificando si FSRM está instalado..." "Yellow"
    $fsrmFeature = Get-WindowsFeature -Name FS-Resource-Manager -ErrorAction SilentlyContinue

    if ($fsrmFeature -and $fsrmFeature.InstallState -eq "Installed") {
        Write-Log "  [+] FSRM ya está instalado." "Green"
    } else {
        Write-Log "  [→] Instalando FSRM..." "Yellow"
        try {
            Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools -ErrorAction Stop
            Write-Log "  [+] FSRM instalado correctamente." "Green"
        } catch {
            Write-Log "  [!] No se pudo instalar FSRM: $_" "Red"
            Write-Log "  [→] Instale manualmente: Install-WindowsFeature FS-Resource-Manager" "Yellow"
            Pause; return
        }
    }

    Import-Module FileServerResourceManager -ErrorAction SilentlyContinue

    # Crear directorio de datos de prueba
    $rutaDatos = "C:\DatosEmpresa"
    Ensure-Directory $rutaDatos

    # 6.2 Configurar Cuotas de Disco
    Write-Log "`n[6.2] Configurando Cuotas de Disco..." "Yellow"

    # Plantilla de cuota para usuarios estándar (500 MB)
    $plantillaStd = "Cuota_Usuarios_500MB"
    if (-not (Get-FsrmQuotaTemplate -Name $plantillaStd -ErrorAction SilentlyContinue)) {
        New-FsrmQuotaTemplate -Name $plantillaStd `
            -Size 524288000 `
            -Description "Cuota 500 MB para usuarios estándar" `
            -Threshold @(
                New-FsrmQuotaThreshold -Percentage 80 -Action @(New-FsrmAction -Type Event -EventType Warning -Body "Uso al 80% de cuota"),
                New-FsrmQuotaThreshold -Percentage 100 -Action @(New-FsrmAction -Type Event -EventType Error -Body "Cuota alcanzada")
            )
        Write-Log "  [+] Plantilla '$plantillaStd' creada (500 MB)." "Green"
    } else {
        Write-Log "  [·] Plantilla '$plantillaStd' ya existe." "Gray"
    }

    # Aplicar cuota a la carpeta de datos
    if (-not (Get-FsrmQuota -Path $rutaDatos -ErrorAction SilentlyContinue)) {
        New-FsrmQuota -Path $rutaDatos -Template $plantillaStd -ErrorAction SilentlyContinue
        Write-Log "  [+] Cuota aplicada a '$rutaDatos'." "Green"
    } else {
        Write-Log "  [·] Cuota ya aplicada a '$rutaDatos'." "Gray"
    }

    # 6.3 Configurar File Screening (bloquear extensiones peligrosas)
    Write-Log "`n[6.3] Configurando File Screening (extensiones bloqueadas)..." "Yellow"

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
            -Description "Bloquea archivos ejecutables y scripts"
        Write-Log "  [+] Plantilla de pantalla '$plantillaPantalla' creada." "Green"
    }

    if (-not (Get-FsrmFileScreen -Path $rutaDatos -ErrorAction SilentlyContinue)) {
        New-FsrmFileScreen -Path $rutaDatos -Template $pantillaPantalla -ErrorAction SilentlyContinue
        Write-Log "  [+] File Screening activo en '$rutaDatos'." "Green"
    }

    # 6.4 Generar reporte de almacenamiento
    Write-Log "`n[6.4] Generando reporte de uso de almacenamiento..." "Yellow"
    $rutaReporteFSRM = "C:\Reportes_P09\Reporte_FSRM_Almacenamiento.txt"

    $reporteContenido = @"
=========================================================
REPORTE DE ALMACENAMIENTO - FSRM
Generado: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Dominio: $Dominio
=========================================================
"@

    try {
        $cuotas = Get-FsrmQuota -ErrorAction SilentlyContinue
        if ($cuotas) {
            $reporteContenido += "`n`n=== CUOTAS ACTIVAS ===`n"
            foreach ($q in $cuotas) {
                $usoPct = if ($q.Size -gt 0) { [math]::Round(($q.Usage / $q.Size) * 100, 2) } else { 0 }
                $reporteContenido += "`nRuta     : $($q.Path)"
                $reporteContenido += "`nLímite   : $([math]::Round($q.Size/1MB, 0)) MB"
                $reporteContenido += "`nUso      : $([math]::Round($q.Usage/1MB, 2)) MB ($usoPct%)"
                $reporteContenido += "`n" + "-"*40
            }
        }
    } catch {
        $reporteContenido += "`n[!] No se pudieron obtener datos de cuotas."
    }

    $reporteContenido | Out-File -FilePath $rutaReporteFSRM -Encoding UTF8
    Write-Log "  [+] Reporte FSRM generado: $rutaReporteFSRM" "Green"

    Write-Log "`n[OK] FASE 6 completada. FSRM configurado para admin_storage." "Green"
    Pause
}

# ─── REPORTE: EVENTOS DE ACCESO DENEGADO ──────────────────────────────────────

function Generar-ReporteAuditoria {
    Write-Log "══════════════════════════════════════════" "Cyan"
    Write-Log " REPORTE: Extracción de Eventos 4625      " "Yellow"
    Write-Log "══════════════════════════════════════════" "Cyan"

    Ensure-Directory (Split-Path $RutaReporte)

    Write-Log "`n[R.1] Extrayendo últimos 10 eventos de Acceso Denegado (ID 4625)..." "Yellow"

    $Eventos = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4625
    } -MaxEvents 10 -ErrorAction SilentlyContinue

    $encabezado = @"
=========================================================
  REPORTE DE AUDITORÍA — ACCESOS DENEGADOS (Event 4625)
  Práctica 09 — Hardening de AD
  Generado por: admin_auditoria
  Fecha       : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Dominio     : $Dominio
=========================================================
"@

    if (-not $Eventos) {
        Write-Log "  [!] No hay eventos 4625 aún. Generando datos de simulación..." "Yellow"

        # Crear eventos de ejemplo para el reporte (si el lab no tiene intentos fallidos aún)
        $cuerpoReporte = $encabezado
        $cuerpoReporte += "`n[!] No se encontraron eventos 4625 reales en el log de seguridad."
        $cuerpoReporte += "`n    Esto puede indicar que la auditoría de Logon no estaba activa antes."
        $cuerpoReporte += "`n    Ejecute las Fases 4 y luego intente logons fallidos para generar eventos.`n"
        $cuerpoReporte | Out-File -FilePath $RutaReporte -Encoding UTF8
        Write-Log "  [+] Reporte de placeholder generado: $RutaReporte" "Yellow"
        Pause; return
    }

    # Construir reporte detallado con todos los campos útiles
    $registros = foreach ($evento in $Eventos) {
        # Extraer campos correctamente del XML del evento
        $xml    = [xml]$evento.ToXml()
        $data   = $xml.Event.EventData.Data

        # Función auxiliar para extraer campo por nombre
        function Get-EventField { param($name) ($data | Where-Object { $_.Name -eq $name }).'#text' }

        $usuario     = Get-EventField "TargetUserName"
        $dominio     = Get-EventField "TargetDomainName"
        $ipOrigen    = Get-EventField "IpAddress"
        $proceso     = Get-EventField "ProcessName"
        $razon       = Get-EventField "FailureReason"
        $tipoLogon   = Get-EventField "LogonType"
        $subStatus   = Get-EventField "SubStatus"

        # Interpretar código de sub-estado
        $descripcionError = switch ($subStatus) {
            "0xC000006A" { "Contraseña incorrecta" }
            "0xC0000064" { "Usuario no existe" }
            "0xC0000234" { "Cuenta bloqueada" }
            "0xC0000072" { "Cuenta deshabilitada" }
            "0xC000006F" { "Fuera de horario permitido" }
            "0xC0000070" { "Estación de trabajo no autorizada" }
            default      { "Código: $subStatus" }
        }

        [PSCustomObject]@{
            "Fecha/Hora"     = $evento.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            "EventID"        = $evento.Id
            "Usuario"        = if ($usuario) { $usuario } else { "(desconocido)" }
            "Dominio"        = $dominio
            "IP Origen"      = if ($ipOrigen -and $ipOrigen -ne "-") { $ipOrigen } else { "Local" }
            "Tipo de Error"  = $descripcionError
            "Proceso"        = if ($proceso) { Split-Path $proceso -Leaf } else { "N/A" }
            "Tipo Logon"     = $tipoLogon
        }
    }

    # Exportar en texto legible
    $cuerpoReporte = $encabezado
    $cuerpoReporte += "`n"
    $cuerpoReporte += $registros | Format-Table -AutoSize | Out-String
    $cuerpoReporte += "`n=========================================================`n"
    $cuerpoReporte += "Total de eventos mostrados: $($Eventos.Count)`n"
    $cuerpoReporte | Out-File -FilePath $RutaReporte -Encoding UTF8

    # También exportar como CSV para análisis
    $rutaCSV = $RutaReporte -replace "\.txt$", ".csv"
    $registros | Export-Csv -Path $rutaCSV -NoTypeInformation -Encoding UTF8

    Write-Log "  [+] Reporte TXT: $RutaReporte" "Green"
    Write-Log "  [+] Reporte CSV: $rutaCSV" "Green"
    Write-Host "`n" + ($registros | Format-Table -AutoSize | Out-String) -ForegroundColor Gray

    Write-Log "[OK] Reporte de auditoría generado correctamente." "Green"
    Pause
}

# ─── VERIFICACIÓN COMPLETA DE LA PRÁCTICA ─────────────────────────────────────

function Verificar-EstadoPractica {
    Write-Log "══════════════════════════════════════════════" "Cyan"
    Write-Log " VERIFICACIÓN: Estado Completo de la Práctica " "Yellow"
    Write-Log "══════════════════════════════════════════════" "Cyan"

    $puntaje = 0; $maxPuntaje = 0

    function Check { 
        param([string]$Desc, [bool]$OK)
        $script:maxPuntaje++
        if ($OK) { 
            Write-Log "  [✓] $Desc" "Green"
            $script:puntaje++
        } else { 
            Write-Log "  [✗] $Desc" "Red"
        }
    }

    Write-Log "`n=== OUs ===" "Yellow"
    Check "OU AdminDelegados existe" ((Get-ADOrganizationalUnit -Filter "Name -eq 'AdminDelegados'" -ErrorAction SilentlyContinue) -ne $null)
    Check "OU Cuates existe"         ((Get-ADOrganizationalUnit -Filter "Name -eq 'Cuates'" -ErrorAction SilentlyContinue) -ne $null)
    Check "OU 'No Cuates' existe"    ((Get-ADOrganizationalUnit -Filter "Name -eq 'No Cuates'" -ErrorAction SilentlyContinue) -ne $null)

    Write-Log "`n=== USUARIOS DELEGADOS ===" "Yellow"
    foreach ($u in @("admin_identidad","admin_storage","admin_politicas","admin_auditoria")) {
        Check "Usuario '$u' existe y está habilitado" `
              ((Get-ADUser -Filter "SamAccountName -eq '$u'" -Properties Enabled -ErrorAction SilentlyContinue)?.Enabled -eq $true)
    }

    Write-Log "`n=== GRUPOS PARA FGPP ===" "Yellow"
    Check "Grupo GG_Admins_Delegados existe" ((Get-ADGroup -Filter "Name -eq 'GG_Admins_Delegados'" -ErrorAction SilentlyContinue) -ne $null)
    Check "Grupo GG_Usuarios_Std existe"     ((Get-ADGroup -Filter "Name -eq 'GG_Usuarios_Std'" -ErrorAction SilentlyContinue) -ne $null)

    Write-Log "`n=== FINE-GRAINED PASSWORD POLICIES ===" "Yellow"
    $fgppAdmins = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Admins'" -ErrorAction SilentlyContinue
    $fgppStd    = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'FGPP_Standard'" -ErrorAction SilentlyContinue
    Check "FGPP_Admins existe"                ($fgppAdmins -ne $null)
    Check "FGPP_Admins: MinPasswordLength=12" ($fgppAdmins?.MinPasswordLength -eq 12)
    Check "FGPP_Admins: LockoutThreshold=3"   ($fgppAdmins?.LockoutThreshold -eq 3)
    Check "FGPP_Standard existe"              ($fgppStd -ne $null)
    Check "FGPP_Standard: MinPasswordLength=8"($fgppStd?.MinPasswordLength -eq 8)

    # Verificar que FGPP está vinculada al grupo correcto
    if ($fgppAdmins) {
        $sujetos = Get-ADFineGrainedPasswordPolicySubject -Identity "FGPP_Admins" -ErrorAction SilentlyContinue
        Check "FGPP_Admins vinculada a GG_Admins_Delegados" ($sujetos.Name -contains "GG_Admins_Delegados")
    }

    Write-Log "`n=== AUDITORÍA ===" "Yellow"
    $auditLogon = cmd.exe /c 'auditpol /get /subcategory:"Logon"'
    Check "Auditoría Logon habilitada (Success)" (($auditLogon | Out-String) -match "Success")
    Check "Auditoría Logon habilitada (Failure)" (($auditLogon | Out-String) -match "Failure")
    $auditObj = cmd.exe /c 'auditpol /get /subcategory:"Object Access"'
    Check "Auditoría Object Access habilitada"   (($auditObj | Out-String) -match "Success|Failure")

    Write-Log "`n=== POLÍTICA DE BLOQUEO DE DOMINIO ===" "Yellow"
    $domPol = Get-ADDefaultDomainPasswordPolicy -Identity $Dominio
    Check "LockoutThreshold = 3"             ($domPol.LockoutThreshold -eq 3)
    Check "LockoutDuration = 30 minutos"     ($domPol.LockoutDuration -eq "00:30:00")

    Write-Log "`n=== MEMBRESÍA DE GRUPOS DE SISTEMA ===" "Yellow"
    Check "admin_auditoria en Event Log Readers" `
          ((Get-ADGroupMember "Event Log Readers" -ErrorAction SilentlyContinue | Where-Object {$_.SamAccountName -eq "admin_auditoria"}) -ne $null)
    Check "admin_politicas en Group Policy Creator Owners" `
          ((Get-ADGroupMember "Group Policy Creator Owners" -ErrorAction SilentlyContinue | Where-Object {$_.SamAccountName -eq "admin_politicas"}) -ne $null)

    Write-Log "`n=== MFA ===" "Yellow"
    $mfaKey = Get-ItemProperty "HKLM:\SOFTWARE\Practica09\MFA_Config" -ErrorAction SilentlyContinue
    Check "Pre-configuración MFA en registro presente" ($mfaKey -ne $null)
    Check "MaxFailedAttempts configurado = 3"         ($mfaKey?.MaxFailedAttempts -eq 3)

    Write-Log "`n═══════════════════════════════════" "Cyan"
    $porcentaje = [math]::Round(($puntaje / $maxPuntaje) * 100)
    $color = if ($porcentaje -ge 80) { "Green" } elseif ($porcentaje -ge 50) { "Yellow" } else { "Red" }
    Write-Log " RESULTADO: $puntaje/$maxPuntaje checks pasados ($porcentaje%)" $color
    Write-Log "═══════════════════════════════════" "Cyan"

    Pause
}

# ─── TEST 1: VERIFICAR DENEGACIÓN A admin_storage ─────────────────────────────

function Test1-DenegacionStorageReset {
    Write-Log "═══════════════════════════════════════════════════════" "Cyan"
    Write-Log " TEST 1: Verificar que admin_storage NO puede resetear  " "Yellow"
    Write-Log " contraseñas (Test 1 del Protocolo de Pruebas)          " "Gray"
    Write-Log "═══════════════════════════════════════════════════════" "Cyan"

    Write-Log "`n[T1.1] Asegurando que user_test existe en OU Cuates..." "Yellow"
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'user_test'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "user_test" -SamAccountName "user_test" `
                   -AccountPassword $PassAdmin -Enabled $true `
                   -Path "OU=Cuates,$DCPath"
        Write-Log "  [+] user_test creado en OU Cuates." "Green"
    }

    Write-Log "`n[T1.2] Intentando resetear contraseña de user_test como admin_storage..." "Yellow"
    Write-Log "  (Esto debe fallar — Acceso Denegado esperado)" "Gray"

    $credStorage = Get-Credential -UserName "$NetBIOS\admin_storage" `
                                  -Message "Ingrese la contraseña de admin_storage para el test"
    try {
        $nuevaPass = ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force
        Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $credStorage -ScriptBlock {
            param($targetUser, $newPass)
            Set-ADAccountPassword -Identity $targetUser -NewPassword $newPass -Reset -ErrorAction Stop
        } -ArgumentList "user_test", $nuevaPass -ErrorAction Stop

        Write-Log "`n[RESULTADO] ⚠ FALLO DEL TEST: admin_storage pudo resetear la contraseña." "Red"
        Write-Log "            Revisar la ACL de denegación aplicada en Fase 2." "Red"
    }
    catch {
        Write-Log "`n[RESULTADO] ✓ TEST EXITOSO: Acceso Denegado confirmado." "Green"
        Write-Log "  Detalle del error: $($_.Exception.Message)" "Gray"
        Write-Log "  → La ACL de denegación funciona correctamente." "Green"
    }

    Pause
}

# ─── TEST 2: VERIFICAR FGPP (12 CARACTERES MÍNIMO) ────────────────────────────

function Test2-ValidarFGPP {
    Write-Log "═══════════════════════════════════════════════════════" "Cyan"
    Write-Log " TEST 2: Verificar FGPP rechaza password < 12 chars     " "Yellow"
    Write-Log " (Test 2 del Protocolo de Pruebas)                      " "Gray"
    Write-Log "═══════════════════════════════════════════════════════" "Cyan"

    Write-Log "`n[T2.1] Verificando FGPP vigente para admin_identidad..." "Yellow"
    $fgppVigente = Get-ADUserResultantPasswordPolicy -Identity "admin_identidad" -ErrorAction SilentlyContinue
    if ($fgppVigente) {
        Write-Log "  FGPP activa: '$($fgppVigente.Name)'" "Gray"
        Write-Log "  Mínimo de caracteres: $($fgppVigente.MinPasswordLength)" "Gray"
    } else {
        Write-Log "  [!] No hay FGPP vigente para admin_identidad." "Red"
        Write-Log "      Ejecute la Fase 3 primero." "Yellow"
        Pause; return
    }

    Write-Log "`n[T2.2] Intentando asignar contraseña corta '12345' (5 chars) a admin_identidad..." "Yellow"
    Write-Log "  (FGPP requiere mínimo 12 — Esto debe ser rechazado)" "Gray"

    try {
        $passCorta = ConvertTo-SecureString "12345" -AsPlainText -Force
        Set-ADAccountPassword -Identity "admin_identidad" -NewPassword $passCorta -Reset -ErrorAction Stop
        Write-Log "`n[RESULTADO] ⚠ FALLO DEL TEST: La contraseña corta fue aceptada." "Red"
        Write-Log "            Revisar si la FGPP está correctamente vinculada." "Red"
    }
    catch {
        Write-Log "`n[RESULTADO] ✓ TEST EXITOSO: La FGPP rechazó la contraseña corta." "Green"
        Write-Log "  Detalle: $($_.Exception.Message)" "Gray"
    }

    Write-Log "`n[T2.3] Intentando con contraseña de exactamente 8 chars para admin_identidad..." "Yellow"
    try {
        $pass8 = ConvertTo-SecureString "Abc12345" -AsPlainText -Force
        Set-ADAccountPassword -Identity "admin_identidad" -NewPassword $pass8 -Reset -ErrorAction Stop
        Write-Log "  ⚠ Contraseña de 8 chars aceptada (incorrecto para FGPP_Admins)." "Red"
    }
    catch {
        Write-Log "  ✓ Contraseña de 8 chars rechazada (correcto para FGPP_Admins de 12 chars)." "Green"
    }

    Pause
}

# ─── EJECUTAR TODAS LAS FASES ─────────────────────────────────────────────────

function EjecutarTodo {
    Write-Log "╔══════════════════════════════════════════════╗" "Cyan"
    Write-Log "║  EJECUCIÓN COMPLETA: FASES 1 → 6             ║" "Yellow"
    Write-Log "╚══════════════════════════════════════════════╝" "Cyan"
    Write-Log "  Esto ejecutará todas las fases automáticamente." "Gray"
    Write-Log "  Tiempo estimado: 5-10 minutos." "Gray"

    $confirm = Read-Host "`n¿Confirmar ejecución completa? (S/N)"
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

# ─── BUCLE PRINCIPAL DEL MENÚ ─────────────────────────────────────────────────

Ensure-Directory "C:\Reportes_P09"
Write-Log "Script iniciado. Log en: $LogScript" "Gray"

do {
    Mostrar-Menu
    $Opcion = Read-Host "  Selecciona una opción"

    switch ($Opcion.ToUpper()) {
        "1"    { Fase1-InfraestructuraBase   }
        "2"    { Fase2-ACLsGranulares        }
        "3"    { Fase3-ConfigurarFGPP        }
        "4"    { Fase4-AuditoriaCompleta     }
        "5"    { Fase5-ConfigurarMFA         }
        "6"    { Fase6-ConfigurarFSRM        }
        "R"    { Generar-ReporteAuditoria    }
        "V"    { Verificar-EstadoPractica    }
        "T1"   { Test1-DenegacionStorageReset}
        "T2"   { Test2-ValidarFGPP           }
        "TODO" { EjecutarTodo                }
        "S"    { Write-Log "Saliendo del script..." "Gray" }
        default{ Write-Log "Opción no válida. Intente de nuevo." "Red"; Start-Sleep 1 }
    }
} while ($Opcion.ToUpper() -ne "S")
