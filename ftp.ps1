# ================================================================
# ADMINISTRADOR FTP ROBUSTO - WINDOWS SERVER
# Cumple todos los requerimientos de la práctica
# ================================================================

# --- 0. VERIFICAR PRIVILEGIOS DE ADMINISTRADOR ---
function Verificar_Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[ERROR] Este script debe ejecutarse como Administrador." -ForegroundColor Red
        exit 1
    }
}

# --- SISTEMA DE LOGS ---
$LogPath = "C:\FTP\logs\admin_ftp.log"

function Write-Log {
    param ([string]$Mensaje, [string]$Nivel = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Linea     = "[$Timestamp] [$Nivel] $Mensaje"
    $LogDir    = Split-Path $LogPath
    if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
    Add-Content -Path $LogPath -Value $Linea
    switch ($Nivel) {
        "ERROR"   { Write-Host $Linea -ForegroundColor Red    }
        "WARNING" { Write-Host $Linea -ForegroundColor Yellow }
        "OK"      { Write-Host $Linea -ForegroundColor Green  }
        default   { Write-Host $Linea -ForegroundColor Cyan   }
    }
}

# ================================================================
# 1. INSTALACIÓN E IDEMPOTENCIA DEL SERVICIO
# ================================================================
function Setup_Entorno_Windows {
    $ftpFeature = Get-WindowsFeature -Name "Web-Ftp-Server" -ErrorAction SilentlyContinue
    if ($ftpFeature -and $ftpFeature.Installed) {
        Write-Log "IIS/FTP ya instalado, omitiendo instalación." "INFO"
    } else {
        Write-Log "Instalando IIS y Servicio FTP..." "INFO"
        Install-WindowsFeature Web-Server, Web-Ftp-Server -IncludeManagementTools | Out-Null
        Write-Log "Instalación completada." "OK"
    }

    Import-Module WebAdministration

    # Estructura de directorios
    $Rutas = @(
        "C:\FTP\LocalUser\Public\general",
        "C:\FTP\grupos\reprobados",
        "C:\FTP\grupos\recursadores",
        "C:\FTP\logs"
    )
    foreach ($Ruta in $Rutas) {
        if (-not (Test-Path $Ruta)) {
            New-Item -Path $Ruta -ItemType Directory -Force | Out-Null
            Write-Log "Directorio creado: $Ruta" "INFO"
        }
    }

    # Grupos locales
    foreach ($g in @("reprobados", "recursadores")) {
        if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $g
            Write-Log "Grupo local creado: $g" "OK"
        }
    }

    # Usuario anónimo (ftp_anonymous) para acceso público
    if (-not (Get-LocalUser -Name "ftp_anonymous" -ErrorAction SilentlyContinue)) {
        $anonPass = ConvertTo-SecureString "Anon@FTP2024!" -AsPlainText -Force
        New-LocalUser -Name "ftp_anonymous" -Password $anonPass -PasswordNeverExpires | Out-Null
        Write-Log "Usuario 'ftp_anonymous' creado." "OK"
    }

    # ---- Configurar Sitio FTP ----
    if (-not (Get-Website -Name "ServidorFTP" -ErrorAction SilentlyContinue)) {
        New-WebFtpSite -Name "ServidorFTP" -Port 21 -PhysicalPath "C:\FTP\LocalUser" -Force
        Write-Log "Sitio FTP 'ServidorFTP' creado." "OK"
    }

    # Aislamiento por usuario (carpeta = nombre de usuario)
    Set-ItemProperty "IIS:\Sites\ServidorFTP" `
        -Name ftpServer.userIsolation.mode -Value "IsolateDirectory"

    # ---- ACCESO ANÓNIMO ----
    # Habilitar autenticación anónima en el sitio
    Set-WebConfigurationProperty -Filter "system.ftpServer/security/authentication/anonymousAuthentication" `
        -PSPath "IIS:\Sites\ServidorFTP" -Name enabled -Value $true

    # Mapear usuario anónimo a 'ftp_anonymous'
    Set-WebConfigurationProperty -Filter "system.ftpServer/security/authentication/anonymousAuthentication" `
        -PSPath "IIS:\Sites\ServidorFTP" -Name userName -Value "ftp_anonymous"

    # Habilitar autenticación básica (usuarios locales)
    Set-WebConfigurationProperty -Filter "system.ftpServer/security/authentication/basicAuthentication" `
        -PSPath "IIS:\Sites\ServidorFTP" -Name enabled -Value $true

    # ---- REGLAS DE AUTORIZACIÓN FTP ----
    # Limpiar reglas existentes y crear desde cero
    Clear-WebConfiguration -Filter "system.ftpServer/security/authorization" `
        -PSPath "IIS:\Sites\ServidorFTP" -ErrorAction SilentlyContinue

    # Regla 1: Anónimo → solo lectura en /general
    Add-WebConfiguration -Filter "system.ftpServer/security/authorization" `
        -PSPath "IIS:\Sites\ServidorFTP\Public\general" -Value @{
            accessType  = "Allow"
            users       = "?"           # '?' = usuarios anónimos
            permissions = "Read"
        }

    # Regla 2: Usuarios autenticados → lectura y escritura global
    Add-WebConfiguration -Filter "system.ftpServer/security/authorization" `
        -PSPath "IIS:\Sites\ServidorFTP" -Value @{
            accessType  = "Allow"
            users       = "*"           # '*' = todos los usuarios autenticados
            permissions = "Read,Write"
        }

    # ---- PERMISOS NTFS CARPETA /general PÚBLICA ----
    # ftp_anonymous: solo lectura
    $AclGeneral   = Get-Acl "C:\FTP\LocalUser\Public\general"
    $ArAnonRead   = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "ftp_anonymous", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $AclGeneral.AddAccessRule($ArAnonRead)
    Set-Acl "C:\FTP\LocalUser\Public\general" $AclGeneral

    Restart-Service ftpsvc -Force
    Write-Log "Entorno Windows completamente configurado." "OK"
}

# ================================================================
# FUNCIONES AUXILIARES DE PERMISOS
# ================================================================

# Asigna permisos NTFS de escritura a un usuario sobre una ruta
function Asignar_Permiso_Escritura {
    param ([string]$Ruta, [string]$Usuario)
    $Acl = Get-Acl $Ruta
    $Ar  = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Usuario, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $Acl.SetAccessRule($Ar)
    Set-Acl $Ruta $Acl
}

# Quita permisos NTFS de un usuario sobre una ruta
function Quitar_Permiso {
    param ([string]$Ruta, [string]$Usuario)
    if (-not (Test-Path $Ruta)) { return }
    $Acl   = Get-Acl $Ruta
    $Rules = $Acl.Access | Where-Object { $_.IdentityReference -like "*\$Usuario" -or $_.IdentityReference -eq $Usuario }
    foreach ($Rule in $Rules) { $Acl.RemoveAccessRule($Rule) | Out-Null }
    Set-Acl $Ruta $Acl
}

# ================================================================
# 2. CREACIÓN DE UN USUARIO (función base reutilizable)
# ================================================================
function Crear_Usuario {
    param (
        [string]$User,
        [System.Security.SecureString]$SecurePass,
        [string]$Group          # "reprobados" o "recursadores"
    )

    # Crear cuenta local
    New-LocalUser -Name $User -Password $SecurePass -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -Group $Group -Member $User

    # ---- Estructura de directorios del usuario ----
    # IIS FTP con aislamiento busca: C:\FTP\LocalUser\<usuario>\<usuario>
    $UserRoot = "C:\FTP\LocalUser\$User"
    New-Item -Path "$UserRoot\$User"   -ItemType Directory -Force | Out-Null

    # ---- Permisos NTFS carpeta personal ----
    Asignar_Permiso_Escritura -Ruta "$UserRoot\$User" -Usuario $User

    # ---- Permisos en carpeta de grupo (escritura) ----
    Asignar_Permiso_Escritura -Ruta "C:\FTP\grupos\$Group" -Usuario $User

    # ---- Permisos en /general (escritura) ----
    Asignar_Permiso_Escritura -Ruta "C:\FTP\LocalUser\Public\general" -Usuario $User

    # ---- Enlaces simbólicos (vista en raíz del usuario al hacer login) ----
    # El usuario verá: /general  /reprobados-o-recursadores  /<su_nombre>
    cmd /c mklink /D "$UserRoot\general" "C:\FTP\LocalUser\Public\general" 2>$null | Out-Null
    cmd /c mklink /D "$UserRoot\$Group"  "C:\FTP\grupos\$Group"            2>$null | Out-Null

    Write-Log "Usuario '$User' creado en grupo '$Group'." "OK"
}

# ================================================================
# VALIDACIÓN DE CONTRASEÑA (SecureString)
# ================================================================
function validarContra {
    param ([System.Security.SecureString]$SecurePass)
    $BSTR    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)
    $contra  = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    if ($contra.Length -lt 8 -or $contra.Length -gt 15)   { return $false }
    if ($contra -notmatch "[A-Z]")                          { return $false }
    if ($contra -notmatch "[a-z]")                          { return $false }
    if ($contra -notmatch "\d")                             { return $false }
    if ($contra -notmatch "[^a-zA-Z0-9]")                  { return $false }
    return $true
}

# ================================================================
# 3. MENÚ → CREAR UN USUARIO
# ================================================================
function CrearUsuarioFTP_Menu {
    $User = (Read-Host "Nombre de usuario").Trim()

    if ([string]::IsNullOrWhiteSpace($User)) {
        Write-Log "Nombre de usuario vacío." "WARNING"; return
    }
    if ([bool](Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
        Write-Log "El usuario '$User' ya existe." "WARNING"; return
    }

    $SecurePass = Read-Host "Contrasena (8-15 carac, Mayus, Minus, Num, Especial)" -AsSecureString
    if (-not (validarContra -SecurePass $SecurePass)) {
        Write-Log "La contraseña no cumple los requisitos de seguridad." "ERROR"; return
    }

    Write-Host "Grupo: 1) Reprobados  2) Recursadores"
    $G_Opt = Read-Host "Seleccione grupo"
    if ($G_Opt -ne "1" -and $G_Opt -ne "2") {
        Write-Log "Opción de grupo inválida. Operación cancelada." "WARNING"; return
    }
    $Group = if ($G_Opt -eq "1") { "reprobados" } else { "recursadores" }

    Crear_Usuario -User $User -SecurePass $SecurePass -Group $Group
}

# ================================================================
# 4. CREACIÓN MASIVA DE USUARIOS  ← REQUERIMIENTO FALTANTE
# ================================================================
function CrearUsuariosMasivo {
    $n = Read-Host "¿Cuántos usuarios desea crear?"
    if ($n -notmatch "^\d+$" -or [int]$n -le 0) {
        Write-Log "Número inválido." "WARNING"; return
    }

    for ($i = 1; $i -le [int]$n; $i++) {
        Write-Host "`n--- Usuario $i de $n ---" -ForegroundColor Cyan

        $User = (Read-Host "  Nombre de usuario").Trim()
        if ([string]::IsNullOrWhiteSpace($User)) {
            Write-Log "Nombre vacío, saltando usuario $i." "WARNING"; continue
        }
        if ([bool](Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
            Write-Log "El usuario '$User' ya existe, saltando." "WARNING"; continue
        }

        $SecurePass = Read-Host "  Contrasena (8-15 carac, Mayus, Minus, Num, Especial)" -AsSecureString
        if (-not (validarContra -SecurePass $SecurePass)) {
            Write-Log "Contraseña inválida para '$User', saltando." "ERROR"; continue
        }

        Write-Host "  Grupo: 1) Reprobados  2) Recursadores"
        $G_Opt = Read-Host "  Seleccione grupo"
        if ($G_Opt -ne "1" -and $G_Opt -ne "2") {
            Write-Log "Grupo inválido para '$User', saltando." "WARNING"; continue
        }
        $Group = if ($G_Opt -eq "1") { "reprobados" } else { "recursadores" }

        Crear_Usuario -User $User -SecurePass $SecurePass -Group $Group
    }

    Write-Log "Creación masiva finalizada ($n usuarios procesados)." "OK"
}

# ================================================================
# 5. CAMBIAR GRUPO FTP
# ================================================================
function CambiarGrupoFTP {
    $User = (Read-Host "Nombre de usuario a cambiar de grupo").Trim()

    if (-not [bool](Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
        Write-Log "El usuario '$User' no existe." "WARNING"; return
    }

    $GrupoActual = $null
    foreach ($g in @("reprobados", "recursadores")) {
        $miembros = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        if ($miembros | Where-Object { $_.Name -like "*\$User" -or $_.Name -eq $User }) {
            $GrupoActual = $g
        }
    }

    if ($null -eq $GrupoActual) {
        Write-Log "No se encontró '$User' en ningún grupo FTP." "WARNING"; return
    }

    $GrupoNuevo = if ($GrupoActual -eq "reprobados") { "recursadores" } else { "reprobados" }

    Write-Host "El usuario '$User' está en '$GrupoActual'. ¿Mover a '$GrupoNuevo'? (S/N)"
    if ((Read-Host) -notmatch "^[Ss]$") {
        Write-Log "Operación cancelada." "INFO"; return
    }

    # Cambiar grupo local
    Remove-LocalGroupMember -Group $GrupoActual -Member $User -ErrorAction SilentlyContinue
    Add-LocalGroupMember    -Group $GrupoNuevo  -Member $User

    $UserRoot = "C:\FTP\LocalUser\$User"

    # Quitar permisos del grupo anterior y asignar en el nuevo
    Quitar_Permiso         -Ruta "C:\FTP\grupos\$GrupoActual" -Usuario $User
    Asignar_Permiso_Escritura -Ruta "C:\FTP\grupos\$GrupoNuevo"  -Usuario $User

    # Actualizar enlace simbólico
    $LinkAntiguo = "$UserRoot\$GrupoActual"
    $LinkNuevo   = "$UserRoot\$GrupoNuevo"
    if (Test-Path $LinkAntiguo) { cmd /c rmdir "$LinkAntiguo" | Out-Null }
    if (-not (Test-Path $LinkNuevo)) {
        cmd /c mklink /D "$LinkNuevo" "C:\FTP\grupos\$GrupoNuevo" | Out-Null
    }

    Write-Log "Usuario '$User' movido de '$GrupoActual' a '$GrupoNuevo'." "OK"
}

# ================================================================
# 6. ELIMINAR USUARIO FTP
# ================================================================
function EliminarUsuarioFTP {
    $User = (Read-Host "Nombre de usuario a eliminar").Trim()

    if (-not [bool](Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
        Write-Log "El usuario '$User' no existe." "WARNING"; return
    }

    Write-Host "ADVERTENCIA: Se eliminará '$User' y todos sus archivos." -ForegroundColor Red
    Write-Host "Escriba el nombre del usuario para confirmar:"
    if ((Read-Host) -ne $User) {
        Write-Log "Confirmación incorrecta. Operación cancelada." "WARNING"; return
    }

    # Quitar permisos en carpetas compartidas
    Quitar_Permiso -Ruta "C:\FTP\LocalUser\Public\general"   -Usuario $User
    foreach ($g in @("reprobados", "recursadores")) {
        Quitar_Permiso -Ruta "C:\FTP\grupos\$g" -Usuario $User
        Remove-LocalGroupMember -Group $g -Member $User -ErrorAction SilentlyContinue
    }

    Remove-LocalUser -Name $User

    $UserPath = "C:\FTP\LocalUser\$User"
    if (Test-Path $UserPath) { Remove-Item -Path $UserPath -Recurse -Force }

    Write-Log "Usuario '$User' eliminado correctamente." "OK"
}

# ================================================================
# 7. LISTAR USUARIOS POR GRUPO
# ================================================================
function ListarUsuariosFTP {
    Write-Host "`n--- Usuarios FTP por grupo ---" -ForegroundColor Cyan
    foreach ($g in @("reprobados", "recursadores")) {
        Write-Host "`nGrupo: $g" -ForegroundColor Yellow
        $miembros = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        if ($miembros) { $miembros | ForEach-Object { Write-Host "  - $($_.Name)" } }
        else            { Write-Host "  (sin usuarios)" }
    }
    Write-Host ""
}

# ================================================================
# INICIO DEL SCRIPT
# ================================================================
Verificar_Admin
Setup_Entorno_Windows

do {
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "     ADMINISTRADOR FTP WINDOWS SERVER     " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "1. Crear un Usuario"
    Write-Host "2. Creacion Masiva de Usuarios"
    Write-Host "3. Cambiar Usuario de Grupo"
    Write-Host "4. Eliminar Usuario"
    Write-Host "5. Listar Usuarios por Grupo"
    Write-Host "6. Reiniciar Servicio FTP"
    Write-Host "7. Salir"
    Write-Host "------------------------------------------"
    $opcion = Read-Host "Seleccione una opcion"

    switch ($opcion) {
        "1" { CrearUsuarioFTP_Menu   }
        "2" { CrearUsuariosMasivo    }
        "3" { CambiarGrupoFTP        }
        "4" { EliminarUsuarioFTP     }
        "5" { ListarUsuariosFTP      }
        "6" {
            Restart-Service ftpsvc -Force
            Write-Log "Servicio FTPSVC reiniciado manualmente." "OK"
        }
        "7" { Write-Log "Sesión cerrada." "INFO"; exit }
        Default { Write-Host "Opcion no valida." -ForegroundColor Yellow }
    }
} while ($true)
