# ============================================================
# ssh_manager.ps1 — SSH Manager (Windows Server 2022)
# Uso: PowerShell -ExecutionPolicy Bypass -File ssh_manager.ps1
# ============================================================

# ════════════════════════════════════════════════════════════
# VALIDACIONES
# ════════════════════════════════════════════════════════════

# Verifica que corra como Administrador
$user      = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($user)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Ejecuta PowerShell como Administrador." -ForegroundColor Red
    exit 1
}

# Valida formato de IP
function Validar-IP {
    param([string]$ip)
    if ($ip -match '^(\d{1,3}\.){3}\d{1,3}$') {
        foreach ($oct in $ip.Split('.')) {
            if ([int]$oct -gt 255) { return $false }
        }
        return $true
    }
    return $false
}

# Pide una IP hasta que sea valida
function Pedir-IP {
    param([string]$prompt)
    while ($true) {
        $ip = Read-Host $prompt
        if (Validar-IP $ip) { return $ip }
        Write-Host "[ERROR] IP invalida: '$ip'. Intenta de nuevo." -ForegroundColor Red
    }
}

# ════════════════════════════════════════════════════════════
# FUNCIONES PRINCIPALES
# ════════════════════════════════════════════════════════════

function Instalar-Servidor {
    Write-Host "--- INSTALANDO SSH EN WINDOWS ---" -ForegroundColor Cyan

    # Verificar si ya esta instalado antes de intentar instalar
    $capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($null -eq $capability) {
        Write-Host "[ERROR] No se encontro la caracteristica OpenSSH.Server." -ForegroundColor Red
        return
    }

    if ($capability.State -eq 'Installed') {
        Write-Host "[INFO]  OpenSSH Server ya esta instalado." -ForegroundColor Cyan
    } else {
        Write-Host "[INFO]  Instalando OpenSSH Server..." -ForegroundColor Cyan
        Add-WindowsCapability -Online -Name $capability.Name | Out-Null
        Write-Host "[OK]    OpenSSH Server instalado." -ForegroundColor Green
    }

    # Configurar servicio
    try {
        Set-Service   -Name sshd -StartupType Automatic
        Start-Service -Name sshd
        Write-Host "[OK]    Servicio sshd iniciado en modo automatico." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] No se pudo iniciar el servicio sshd: $_" -ForegroundColor Red
        return
    }

    # Configurar firewall
    if (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue) {
        Write-Host "[INFO]  Regla de Firewall ya existe." -ForegroundColor Cyan
    } else {
        New-NetFirewallRule `
            -Name        "OpenSSH-Server-In-TCP" `
            -DisplayName "OpenSSH Server (sshd)" `
            -Enabled     True `
            -Direction   Inbound `
            -Protocol    TCP `
            -LocalPort   22 `
            -Action      Allow | Out-Null
        Write-Host "[OK]    Regla de Firewall creada: puerto 22 permitido." -ForegroundColor Green
    }

    # Mostrar IP para conectarse
    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -First 1 -ExpandProperty IPAddress)

    Write-Host "[OK]    SSH listo. Conectate con: ssh $env:USERNAME@$ip" -ForegroundColor Green
}

function Conectar-Remoto {
    # Pedir IP con validacion
    $ip = Pedir-IP "IP del servidor remoto"

    # Verificar conectividad antes de conectar
    Write-Host "[INFO]  Verificando conectividad con $ip ..." -ForegroundColor Cyan
    if (-not (Test-Connection -ComputerName $ip -Count 2 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Host "[WARN]  $ip no responde al ping." -ForegroundColor Yellow
        $resp = Read-Host "Intentar conectarse de todos modos? (s/n)"
        if ($resp -ne "s") { return }
    } else {
        Write-Host "[OK]    $ip responde. Red OK." -ForegroundColor Green
    }

    # Pedir usuario no vacio
    $user = ""
    while ([string]::IsNullOrWhiteSpace($user)) {
        $user = Read-Host "Usuario"
        if ([string]::IsNullOrWhiteSpace($user)) {
            Write-Host "[ERROR] El usuario no puede estar vacio." -ForegroundColor Red
        }
    }

    Write-Host "[INFO]  Conectando a $user@$ip ..." -ForegroundColor Cyan
    Write-Host "(Para cerrar la sesion escribe: exit)" -ForegroundColor Yellow

    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$user@$ip"

    Write-Host "[OK]    Sesion cerrada." -ForegroundColor Green
}

# ════════════════════════════════════════════════════════════
# MENU
# ════════════════════════════════════════════════════════════

while ($true) {
    Write-Host "`n--- SSH MANAGER ---" -ForegroundColor Cyan
    Write-Host "1) Instalar y Activar Servidor SSH"
    Write-Host "2) Conectarse a otro servidor"
    Write-Host "3) Salir"
    $op = Read-Host "Selecciona una opcion"
    switch ($op) {
        "1" { Instalar-Servidor }
        "2" { Conectar-Remoto   }
        "3" { exit              }
        Default { Write-Host "[WARN] Opcion no valida." -ForegroundColor Yellow }
    }
}
