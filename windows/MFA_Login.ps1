# =========================================================================
# MFA_Login.ps1 - Autenticacion MFA con TOTP (Clave unica por usuario)
# Practica 09 - Hardening AD
# Dominio: carlos.local
# Servidor: 192.168.56.10
# Ejecutar como GPO Logon Script
# =========================================================================

# --- CONFIGURACION ---
$MaxIntentos = 3
$BloqueoMin  = 30
$LogMFA      = "\\192.168.56.10\Reportes_P09\MFA\Log_MFA.txt"

# --- CLAVES TOTP POR USUARIO (Base32 unica por usuario) ---
# IMPORTANTE: Cada usuario debe escanear su propio QR con Google Authenticator
$ClavesPorUsuario = @{
    "administrador"  = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    "admin_identidad"= "JBSWY3DPEHPK3PXP4Z2DSMJSHUYTSLLF"
    "admin_storage"  = "KRUGKIDROVUWG2ZJNVSQ6ZDBORXXG4DF"
    "admin_politicas"= "MFRA2YLBONSWC3TBNVSQ2YLBONSWC3TB"
    "admin_auditoria"= "NFXGO3LBNZSQ6ZDBORXXG4DFNZSS4Y3P"
    "jlopez"         = "OJSXG2LTOVZGS3THEBWWC2LOEBWWC2LO"
    "mgarcia"        = "PBUW24DMPEQG22LOEBWWC2LOEBWWC2LO"
    "rperez"         = "QCVKWIDEN5RHA3DFMFRA2YLBONSWC3TB"
    "amorales"       = "RDWLXJFEO6SIB4EGNFXGO3LBNZSQ6ZDB"
    "user_test"      = "SEXMYKGFP7TJC5FHOGYHQ4LCOA4Q7ACJ"
}

# --- FUNCIONES TOTP ---
function ConvertFrom-Base32 {
    param([string]$Base32)
    $Base32 = $Base32.ToUpper().TrimEnd("=")
    $base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $bits = ""
    foreach ($c in $Base32.ToCharArray()) {
        $val = $base32Chars.IndexOf($c)
        if ($val -lt 0) { continue }
        $bits += [Convert]::ToString($val, 2).PadLeft(5, '0')
    }
    $bytes = New-Object byte[] ([Math]::Floor($bits.Length / 8))
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($bits.Substring($i * 8, 8), 2)
    }
    return $bytes
}

function Test-TOTPCode {
    param([string]$SecretBase32, [string]$CodigoIngresado)
    $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($offset in @(-1, 0, 1)) {
        $counter      = [Math]::Floor($epoch / 30) + $offset
        $counterBytes = [BitConverter]::GetBytes([long]$counter)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counterBytes) }
        $keyBytes = ConvertFrom-Base32 $SecretBase32
        $hmac     = New-Object System.Security.Cryptography.HMACSHA1
        $hmac.Key = $keyBytes
        $hash     = $hmac.ComputeHash($counterBytes)
        $off      = $hash[$hash.Length - 1] -band 0x0F
        $code     = (($hash[$off]     -band 0x7F) -shl 24) -bor
                    (($hash[$off + 1] -band 0xFF) -shl 16) -bor
                    (($hash[$off + 2] -band 0xFF) -shl 8)  -bor
                     ($hash[$off + 3] -band 0xFF)
        if ($CodigoIngresado -eq ($code % 1000000).ToString("000000")) { return $true }
    }
    return $false
}

function Write-MFALog {
    param([string]$Mensaje, [string]$Estado)
    $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linea = "[$ts] USER=$usuario | ESTADO=$Estado | $Mensaje"
    try {
        $carpeta = Split-Path $LogMFA
        if (-not (Test-Path $carpeta)) {
            New-Item -Path $carpeta -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $LogMFA -Value $linea -ErrorAction Stop
    } catch {
        $backup = "C:\Reportes_P09\MFA\Log_Local_Backup.txt"
        $carpetaLocal = "C:\Reportes_P09\MFA"
        if (-not (Test-Path $carpetaLocal)) {
            New-Item -Path $carpetaLocal -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $backup -Value "[$ts] (BACKUP) $linea" -ErrorAction SilentlyContinue
    }
}

# --- OBTENER USUARIO ACTUAL ---
$usuarioRaw = $env:USERNAME
$usuario    = ($usuarioRaw -replace ".*\\", "" -replace "@.*", "").ToLower()

# --- BUSCAR CLAVE DEL USUARIO ---
$ClaveTOTP = $ClavesPorUsuario[$usuario]

if (-not $ClaveTOTP) {
    Write-Host ""
    Write-Host "  [!] Usuario '$usuario' no tiene clave MFA configurada." -ForegroundColor Yellow
    Write-Host "  [!] Contacta al administrador del dominio." -ForegroundColor Yellow
    Write-MFALog "Usuario sin clave MFA configurada" "SIN_CLAVE"
    exit 0
}

# --- BANNER ---
Clear-Host
Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "     AUTENTICACION MFA REQUERIDA          " -ForegroundColor Yellow
Write-Host "     Usuario : $usuario                   " -ForegroundColor White
Write-Host "     Hora    : $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor White
Write-Host "     Dominio : carlos.local               " -ForegroundColor White
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Abre Google Authenticator en tu celular" -ForegroundColor Gray
Write-Host "  y busca: $usuario@carlos.local" -ForegroundColor Cyan
Write-Host ""

$intentos        = 0
$accesoConcedido = $false

while ($intentos -lt $MaxIntentos) {
    $codigo = Read-Host "  Ingresa tu codigo de Google Authenticator (6 digitos)"

    if (Test-TOTPCode -SecretBase32 $ClaveTOTP -CodigoIngresado $codigo) {
        $accesoConcedido = $true
        Write-Host ""
        Write-Host "  [OK] Token valido. Acceso concedido." -ForegroundColor Green
        Write-Host ""
        Write-MFALog "Token valido. Acceso concedido." "OK"
        Start-Sleep -Seconds 2
        break
    } else {
        $intentos++
        $restantes = $MaxIntentos - $intentos
        Write-Host ""
        Write-Host "  [ERROR] Codigo incorrecto." -ForegroundColor Red
        Write-MFALog "Codigo incorrecto. Intento $intentos de $MaxIntentos" "FALLO"
        if ($restantes -gt 0) {
            Write-Host "  Intentos restantes: $restantes" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}

# --- BLOQUEO TRAS 3 INTENTOS FALLIDOS (TEST 4) ---
if (-not $accesoConcedido) {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Red
    Write-Host "   ACCESO DENEGADO                       " -ForegroundColor Red
    Write-Host "   $MaxIntentos intentos fallidos de MFA  " -ForegroundColor Red
    Write-Host "   Bloqueando cuenta por $BloqueoMin min  " -ForegroundColor Red
    Write-Host "  ========================================" -ForegroundColor Red

    Write-MFALog "3 intentos fallidos. Iniciando bloqueo de cuenta." "BLOQUEADO"

    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        # Disparar intentos fallidos para activar lockout de AD
        $dominio = "carlos.local"
        1..4 | ForEach-Object {
            try {
                $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                    [System.DirectoryServices.AccountManagement.ContextType]::Domain, $dominio)
                $ctx.ValidateCredentials($usuario, "WrongMFA_$_") | Out-Null
            } catch {}
        }

        Start-Sleep -Seconds 2

        $adUser = Get-ADUser -Identity $usuario -Properties LockedOut, BadLogonCount, Enabled -ErrorAction SilentlyContinue

        if ($adUser -and $adUser.LockedOut) {
            Write-MFALog "Cuenta bloqueada en AD. BadLogonCount=$($adUser.BadLogonCount)" "BLOQUEADO_AD"
        } else {
            Disable-ADAccount -Identity $usuario -ErrorAction SilentlyContinue
            Write-MFALog "Cuenta deshabilitada por MFA fallido" "DESHABILITADO"
        }
    } catch {
        Write-MFALog "Error al bloquear cuenta: $_" "ERROR"
    }

    # --- EVIDENCIA TEST 4 ---
    Write-Host ""
    Write-Host "  --- EVIDENCIA TEST 4 ---" -ForegroundColor Cyan
    try {
        $adUser = Get-ADUser -Identity $usuario -Properties LockedOut, BadLogonCount, Enabled -ErrorAction SilentlyContinue
        if ($adUser) {
            Write-Host "  Usuario      : $($adUser.SamAccountName)" -ForegroundColor White
            Write-Host "  LockedOut    : $($adUser.LockedOut)"      -ForegroundColor Red
            Write-Host "  Enabled      : $($adUser.Enabled)"        -ForegroundColor Yellow
            Write-Host "  BadLogonCount: $($adUser.BadLogonCount)"  -ForegroundColor White
            Write-Host "  Timestamp    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        }
    } catch {}

    Write-Host ""
    Write-Host "  TOMA CAPTURA DE ESTA PANTALLA PARA EL REPORTE." -ForegroundColor Cyan
    Write-Host ""
    Read-Host "  Presiona ENTER para salir"

    # Cerrar sesion
    shutdown /l /f
    exit 1
}
