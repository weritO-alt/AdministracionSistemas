


# ════════════════════════════════════════════════════════════
# FUNCIONES UTILITARIAS
# ════════════════════════════════════════════════════════════

function Write-OK   { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green  }
function Write-Info { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan   }
function Write-Err  { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red    }
function Write-Warn { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }

function Verify-Admin {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Err "Ejecuta PowerShell como Administrador."
        exit 1
    }
    Write-OK "Ejecutando como Administrador."
}

function Validate-IP {
    param([string]$ip)
    if ($ip -match '^(\d{1,3}\.){3}\d{1,3}$') {
        $octets = $ip.Split('.')
        foreach ($oct in $octets) {
            if ([int]$oct -gt 255) { return $false }
        }
        return $true
    }
    return $false
}

function Get-ValidIP {
    param([string]$prompt)
    while ($true) {
        $ip = Read-Host $prompt
        if (Validate-IP $ip) { return $ip }
        Write-Err "IP invalida: '$ip'. Intenta de nuevo."
    }
}

function Pause-Menu {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar"
}

function Get-LocalIP {
    return (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -First 1 -ExpandProperty IPAddress)
}

# Verificacion rapida: solo revisa el servicio local, sin consultar Windows Update
function Check-SSHInstalled {
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    return ($null -ne $svc)
}

# ════════════════════════════════════════════════════════════
# OPCION 1 — VERIFICAR INSTALACION SSH LOCAL (rapido)
# ════════════════════════════════════════════════════════════

function Verificar-Instalacion {
    Write-Host ""
    Write-Info "=== Verificando SSH Server en Windows Server 2022 ==="

    # Verificar por servicio (instantaneo, sin internet)
    if (Check-SSHInstalled) {
        Write-OK "OpenSSH Server esta instalado."
    } else {
        Write-Warn "OpenSSH Server NO esta instalado (servicio sshd no encontrado)."
    }

    # Estado del servicio
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Write-OK "Servicio sshd esta ACTIVO."
        } else {
            Write-Warn "Servicio sshd esta INACTIVO (estado: $($svc.Status))."
        }

        if ($svc.StartType -eq "Automatic") {
            Write-OK "sshd configurado para iniciar automaticamente."
        } else {
            Write-Warn "sshd NO inicia automaticamente (tipo: $($svc.StartType))."
        }
    }

    # Verificar regla de firewall
    $rule = Get-NetFirewallRule -Name "sshd" -ErrorAction SilentlyContinue
    if ($rule -and $rule.Enabled -eq "True") {
        Write-OK "Regla de Firewall para puerto 22 esta activa."
    } else {
        Write-Warn "No hay regla de Firewall para el puerto 22."
    }

    # Mostrar IP local
    Write-Host ""
    Write-Info "IP de esta maquina (Windows Server):"
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Format-Table InterfaceAlias, IPAddress -AutoSize
}

# ════════════════════════════════════════════════════════════
# OPCION 2 — INSTALAR Y CONFIGURAR SSH LOCAL
# ════════════════════════════════════════════════════════════

function Instalar-SSH {
    Write-Host ""
    Write-Info "=== Instalando y configurando OpenSSH Server ==="

    # Instalar solo si el servicio no existe
    if (Check-SSHInstalled) {
        Write-Info "OpenSSH Server ya esta instalado."
    } else {
        Write-Info "Instalando OpenSSH Server (esto puede tardar un momento)..."
        $ssh = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
        Add-WindowsCapability -Online -Name $ssh.Name | Out-Null
        Write-OK "OpenSSH Server instalado."
    }

    # Habilitar e iniciar el servicio
    Set-Service -Name sshd -StartupType Automatic
    Start-Service -Name sshd
    Write-OK "Servicio sshd iniciado y configurado para arranque automatico."

    # Configurar regla de Firewall
    $rule = Get-NetFirewallRule -Name "sshd" -ErrorAction SilentlyContinue
    if ($rule) {
        Write-Info "Regla de Firewall para puerto 22 ya existe."
    } else {
        New-NetFirewallRule `
            -Name        "sshd" `
            -DisplayName "OpenSSH Server (sshd)" `
            -Enabled     True `
            -Direction   Inbound `
            -Protocol    TCP `
            -Action      Allow `
            -LocalPort   22 | Out-Null
        Write-OK "Regla de Firewall creada: TCP puerto 22 permitido."
    }

    # PowerShell como shell por defecto
    $regPath = "HKLM:\SOFTWARE\OpenSSH"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name DefaultShell `
        -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    Write-OK "Shell por defecto: PowerShell."

    $ipLocal = Get-LocalIP
    Write-Host ""
    Write-OK "SSH listo. Otras VMs pueden conectarse con:"
    Write-Info "ssh $env:USERNAME@$ipLocal"
}

# ════════════════════════════════════════════════════════════
# OPCION 3 — CONECTARSE A UNA VM EN LA RED INTERNA
# ════════════════════════════════════════════════════════════

function Conectarse-SSH {
    Write-Host ""
    Write-Info "=== Conexion SSH a VM en red interna ==="

    $ipLocal = Get-LocalIP
    Write-Info "Tu IP actual (Windows Server): $ipLocal"
    Write-Host ""

    $server = Get-ValidIP "IP de la VM destino (ej. 192.168.x.x):"

    # Ping rapido con timeout corto
    Write-Info "Verificando conectividad con $server ..."
    $ping = Test-Connection -ComputerName $server -Count 2 -Quiet
    if ($ping) {
        Write-OK "$server responde. Red interna OK."
    } else {
        Write-Warn "$server NO responde al ping."
        $resp = Read-Host "Intentar conectarse de todos modos? (s/n)"
        if ($resp -ne "s") { return }
    }

    $user = ""
    while ([string]::IsNullOrWhiteSpace($user)) {
        $user = Read-Host "Usuario en $server"
        if ([string]::IsNullOrWhiteSpace($user)) {
            Write-Err "El usuario no puede estar vacio."
        }
    }

    Write-Host ""
    Write-Info "Conectando a $user@$server ..."
    Write-Host "(Para cerrar la sesion SSH escribe: exit)" -ForegroundColor Yellow
    Write-Host ""

    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$user@$server"

    Write-Host ""
    Write-OK "Sesion cerrada. De vuelta en Windows Server ($ipLocal)."
}

# ════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ════════════════════════════════════════════════════════════

function Show-Menu {
    Write-Host ""
    
    Write-Host " 1) Verificar instalacion SSH local"
    Write-Host " 2) Instalar y configurar SSH local"
    Write-Host " 3) Conectarse a una VM en red interna"
    Write-Host " 4) Salir"
    Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
}

function Menu-Interactivo {
    while ($true) {
        Show-Menu
        $op = Read-Host "Selecciona una opcion"
        switch ($op) {
            "1" { Verificar-Instalacion ; Pause-Menu }
            "2" { Instalar-SSH          ; Pause-Menu }
            "3" { Conectarse-SSH        ; Pause-Menu }
            "4" { Write-Host "Saliendo..."; exit 0   }
            default { Write-Warn "Opcion invalida."  }
        }
    }
}



Verify-Admin
Menu-Interactivo
