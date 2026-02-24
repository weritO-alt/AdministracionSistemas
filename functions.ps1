# ============================================================
# functions.ps1 — Librería central de funciones
# No ejecutar directamente, es llamado por menus.ps1
# ============================================================

# ────────────────────────────────────────────────────────────
# LOGS Y VALIDACIONES
# ────────────────────────────────────────────────────────────

function Log-Exito { param([string]$texto); Write-Host "[OK]    $texto" -ForegroundColor Green }
function Log-Error { param([string]$texto); Write-Host "[ERROR] $texto" -ForegroundColor Red }
function Log-Aviso { param([string]$texto); Write-Host "[INFO]  $texto" -ForegroundColor Cyan }
function Log-Warn  { param([string]$texto); Write-Host "[WARN]  $texto" -ForegroundColor Yellow }

function Verificar-Admin {
    $identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identidad)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Log-Error "Debes ejecutar PowerShell como ADMINISTRADOR."
        Start-Sleep -Seconds 3
        exit
    }
}

function Pedir-Entero {
    param([string]$Mensaje)
    while ($true) {
        $num = Read-Host "$Mensaje"
        if ([string]::IsNullOrWhiteSpace($num)) { Log-Error "No puede estar vacio."; continue }
        if ($num -match '^\d+$') {
            $valor = [int]$num
            if ($valor -gt 0) { return $valor } else { Log-Error "Debe ser mayor a 0." }
        } else { Log-Error "Solo numeros enteros positivos." }
    }
}

function Obtener-Mascara-Desde-Prefijo {
    param([int]$Prefijo)
    switch ($Prefijo) {
        8  { return "255.0.0.0" }
        16 { return "255.255.0.0" }
        24 { return "255.255.255.0" }
        Default {
            $mascara = [uint32]::MaxValue -shl (32 - $Prefijo)
            $bytes = [BitConverter]::GetBytes([uint32][IPAddress]::HostToNetworkOrder($mascara))
            return (($bytes | ForEach-Object { $_ }) -join ".")
        }
    }
}

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

function Pedir-IP-Segura {
    param([string]$Mensaje, [string]$EsOpcional = "no")
    while ($true) {
        $entrada = (Read-Host "$Mensaje").Trim()
        if ($EsOpcional -eq "si" -and $entrada -eq "") { return "" }
        if ($entrada -eq "") { Log-Error "No lo dejes vacio."; continue }
        if ($entrada -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            if ($entrada -eq "0.0.0.0" -or $entrada -eq "127.0.0.1" -or $entrada -eq "255.255.255.255") {
                Log-Error "IP $entrada NO permitida (Reservada)."
            } else { return $entrada }
        } else { Log-Error "Formato incorrecto. Usa X.X.X.X (0-255)." }
    }
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 1 — DIAGNÓSTICO DEL SISTEMA
# ────────────────────────────────────────────────────────────

function P1-Mostrar-Info {
    Write-Host ""
    Log-Aviso "=== Informacion del Sistema ==="
    Write-Host "  Equipo   : $env:COMPUTERNAME" -ForegroundColor White

    $ips = Get-NetIPAddress -AddressFamily IPv4 |
           Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
           Select-Object -ExpandProperty IPAddress
    Write-Host "  IPs      : $($ips -join ', ')" -ForegroundColor White

    Write-Host ""
    Log-Aviso "Espacio en disco:"
    $disk   = Get-PSDrive C
    $totalGB = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2)
    $usedGB  = [math]::Round($disk.Used / 1GB, 2)
    $freeGB  = [math]::Round($disk.Free / 1GB, 2)
    Write-Host "  Total : $totalGB GB" -ForegroundColor White
    Write-Host "  Usado : $usedGB GB"  -ForegroundColor White
    Write-Host "  Libre : $freeGB GB"  -ForegroundColor White

    Write-Host ""
    Read-Host "Enter para continuar..."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 2 — DHCP
# ────────────────────────────────────────────────────────────

function Instalar-Rol-DHCP {
    Log-Aviso "Verificando DHCP..."
    if ((Get-WindowsFeature DHCP).Installed) {
        Log-Exito "DHCP ya instalado."
    } else {
        $resultado = Install-WindowsFeature DHCP -IncludeManagementTools
        if ($resultado.Success) {
            Log-Exito "Instalacion del rol completada."
        } else {
            Log-Error "Fallo la instalacion del rol DHCP."
            Read-Host "Enter para continuar..."
            return
        }
    }

    Log-Aviso "Creando grupos de seguridad DHCP..."
    netsh dhcp add securitygroups | Out-Null

    Log-Aviso "Autorizando servidor DHCP..."
    try {
        $ipServidor = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -ne "127.0.0.1" } |
            Select-Object -First 1).IPAddress
        Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $ipServidor -ErrorAction SilentlyContinue
        Log-Exito "Servidor DHCP autorizado."
    } catch {
        Log-Aviso "Autorizacion omitida (puede que ya este autorizado o no este en dominio)."
    }

    Log-Aviso "Iniciando servicio DHCP..."
    try {
        Start-Service DhcpServer -ErrorAction Stop
        Log-Exito "Servicio DHCP corriendo."
    } catch {
        Log-Error "No se pudo iniciar el servicio: $_"
    }

    Read-Host "Enter para continuar..."
}

function Configurar-Todo-Scope {
    $servicio = Get-Service -Name DhcpServer -ErrorAction SilentlyContinue
    if (-not $servicio -or $servicio.Status -ne "Running") {
        Log-Error "El servicio DHCP no esta corriendo. Instala primero (Opcion 1)."
        Read-Host "Enter para continuar..."
        return
    }

    Log-Aviso "--- CONFIGURACION DE RED Y SCOPE ---"
    Get-NetAdapter | Select-Object Name, Status | Format-Table -AutoSize

    $NombreInterfaz = Read-Host "Nombre del adaptador [Default: Ethernet 2]"
    if ($NombreInterfaz -eq "") { $NombreInterfaz = "Ethernet 2" }

    $RangoInicio = Pedir-IP-Segura "1. IP Inicio Rango"

    while ($true) {
        $RangoFin = Pedir-IP-Segura "2. IP Fin Rango"
        if ([Version]$RangoFin -gt [Version]$RangoInicio) { break }
        else { Log-Error "La IP Final debe ser mayor a $RangoInicio." }
    }

    $IPServidor = Pedir-IP-Segura "3. IP Estatica del Servidor"

    $Prefijo = Read-Host "4. Prefijo (24, 16, 8) [Default: 24]"
    if ($Prefijo -eq "") { $Prefijo = 24 }
    $Mascara = Obtener-Mascara-Desde-Prefijo ([int]$Prefijo)

    $Gateway = Pedir-IP-Segura "5. Gateway (Enter para omitir)" "si"

    Write-Host ""
    Log-Aviso "DNS primario: $IPServidor (este servidor, forzado automaticamente)"
    $DnsSecundario = Pedir-IP-Segura "6. DNS Secundario (ej. 8.8.8.8 - Enter para omitir)" "si"
    Write-Host ""

    $NombreScope  = Read-Host "7. Nombre del Scope"
    $TiempoLease  = Pedir-Entero "8. Tiempo Lease (segundos)"

    Log-Aviso "Configurando IP Estatica en la interfaz..."
    try {
        Remove-NetIPAddress -InterfaceAlias $NombreInterfaz -Confirm:$false -ErrorAction SilentlyContinue
        if ($Gateway) {
            New-NetIPAddress -InterfaceAlias $NombreInterfaz -IPAddress $IPServidor -PrefixLength $Prefijo -DefaultGateway $Gateway -ErrorAction SilentlyContinue
        } else {
            New-NetIPAddress -InterfaceAlias $NombreInterfaz -IPAddress $IPServidor -PrefixLength $Prefijo -ErrorAction SilentlyContinue
        }
        if ($DnsSecundario -ne "") {
            Set-DnsClientServerAddress -InterfaceAlias $NombreInterfaz -ServerAddresses @($IPServidor, $DnsSecundario)
        } else {
            Set-DnsClientServerAddress -InterfaceAlias $NombreInterfaz -ServerAddresses @($IPServidor)
        }
        Log-Exito "IP estatica configurada."
    } catch { Log-Error "Error en IP fija: $_" }

    $partes = $RangoInicio.Split(".")
    $netID  = "$($partes[0]).$($partes[1]).$($partes[2]).0"

    if (Get-DhcpServerv4Scope -ScopeId $netID -ErrorAction SilentlyContinue) {
        Remove-DhcpServerv4Scope -ScopeId $netID -Force
    }

    try {
        Add-DhcpServerv4Scope -Name $NombreScope -StartRange $RangoInicio -EndRange $RangoFin -SubnetMask $Mascara -State Active
        Set-DhcpServerv4Scope -ScopeId $netID -LeaseDuration (New-TimeSpan -Seconds $TiempoLease)

        if ($Gateway) { Set-DhcpServerv4OptionValue -ScopeId $netID -OptionId 3 -Value $Gateway }

        if ($DnsSecundario -ne "") {
            Set-DhcpServerv4OptionValue -ScopeId $netID -OptionId 6 -Value @($IPServidor, $DnsSecundario) -Force
            Log-Exito "DNS vinculado: Primario=$IPServidor  Secundario=$DnsSecundario"
        } else {
            Set-DhcpServerv4OptionValue -ScopeId $netID -OptionId 6 -Value @($IPServidor) -Force
            Log-Exito "DNS vinculado: Primario=$IPServidor"
        }

        try {
            Add-DhcpServerv4ExclusionRange -ScopeId $netID -StartRange $IPServidor -EndRange $IPServidor -ErrorAction SilentlyContinue
            Log-Aviso "IP del servidor ($IPServidor) excluida del rango DHCP."
        } catch {}

    } catch { Log-Error "Fallo en la configuracion del Scope: $_" }

    Restart-Service DhcpServer -Force
    Log-Exito "Configuracion terminada."
    Read-Host "Enter para continuar..."
}

function Monitorear-Clientes {
    Log-Aviso "CLIENTES CONECTADOS (Leases)"
    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if (-not $scopes) {
        Log-Error "No hay scopes configurados."
        Read-Host "Enter para continuar..."
        return
    }
    foreach ($scope in $scopes) {
        Write-Host "`nScope: $($scope.ScopeId) - $($scope.Name)" -ForegroundColor Yellow
        Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue |
            Select-Object IPAddress, HostName, LeaseExpiryTime |
            Format-Table -AutoSize
    }
    Read-Host "Enter para continuar..."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 2 — DNS
# ────────────────────────────────────────────────────────────

function Instalar-DNS {
    Clear-Host
    Log-Aviso "--- INSTALACION DE DNS ---"
    $resultado = Install-WindowsFeature -Name DNS -IncludeManagementTools

    if ($resultado.Success) {
        Import-Module DnsServer -ErrorAction SilentlyContinue
        Start-Service DNS -ErrorAction SilentlyContinue

        Log-Aviso "Configurando firewall para DNS (puerto 53)..."
        try {
            New-NetFirewallRule -DisplayName "DNS Server UDP" -Direction Inbound -Protocol UDP `
                -LocalPort 53 -Action Allow -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallRule -DisplayName "DNS Server TCP" -Direction Inbound -Protocol TCP `
                -LocalPort 53 -Action Allow -ErrorAction SilentlyContinue | Out-Null
            Log-Exito "Firewall configurado: puerto 53 abierto (TCP y UDP)."
        } catch { Log-Aviso "Las reglas de firewall ya existen o no se pudieron crear." }

        try {
            Set-DnsServerSetting -ListeningIPAddress @("0.0.0.0") -ErrorAction SilentlyContinue
            Log-Exito "DNS configurado para escuchar en todas las interfaces."
        } catch { Log-Aviso "Configuracion de interfaces se mantiene por defecto." }

        Log-Exito "DNS instalado y corriendo."
    } else {
        Log-Error "Fallo la instalacion de DNS."
    }

    Read-Host "Enter para continuar..."
}

function Agregar-Dominio-DNS {
    Log-Aviso "--- AGREGAR DOMINIO ---"

    $dominio = Read-Host "Nombre del dominio (ej. reprobados.com)"
    if ([string]::IsNullOrWhiteSpace($dominio)) {
        Log-Error "El dominio no puede estar vacio."
        Read-Host "Enter para continuar..."
        return
    }

    if (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue) {
        Log-Aviso "El dominio '$dominio' ya existe."
        Read-Host "Enter para continuar..."
        return
    }

    $ip = Pedir-IP-Segura "IP para este dominio"

    Add-DnsServerPrimaryZone -Name $dominio -ZoneFile "$dominio.dns"
    Add-DnsServerResourceRecordA     -Name "@"   -ZoneName $dominio -IPv4Address $ip
    Add-DnsServerResourceRecordA     -Name "ns1" -ZoneName $dominio -IPv4Address $ip
    Add-DnsServerResourceRecordCName -Name "www" -HostNameAlias "$dominio." -ZoneName $dominio

    Log-Exito "Dominio '$dominio' agregado con IP $ip."
    Read-Host "Enter para continuar..."
}

function Eliminar-Dominio-DNS {
    Log-Aviso "--- ELIMINAR DOMINIO ---"

    $zonas = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }
    if (-not $zonas) {
        Log-Aviso "No hay dominios activos para eliminar."
        Read-Host "Enter para continuar..."
        return
    }

    Log-Aviso "Dominios disponibles:"
    foreach ($z in $zonas) { Write-Host "  - $($z.ZoneName)" -ForegroundColor White }

    $dominio = Read-Host "`nNombre exacto del dominio a eliminar"
    if ($dominio -eq "") { return }

    if (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue) {
        Remove-DnsServerZone -Name $dominio -Force
        Log-Exito "Dominio '$dominio' eliminado."
    } else {
        Log-Error "Ese dominio no existe en el servidor."
    }

    Read-Host "Enter para continuar..."
}

function Listar-Dominios-DNS {
    Log-Aviso "--- DOMINIOS ACTIVOS ---"

    $zonas = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }
    if (-not $zonas) {
        Log-Aviso "No hay dominios configurados aun."
        Read-Host "Enter para continuar..."
        return
    }

    foreach ($z in $zonas) {
        $record = Get-DnsServerResourceRecord -ZoneName $z.ZoneName -RRType A |
                  Where-Object { $_.HostName -eq "@" } |
                  Select-Object -First 1
        $ip = if ($record) { $record.RecordData.IPv4Address } else { "Sin IP" }
        Write-Host "  $($z.ZoneName) -> $ip" -ForegroundColor White
    }

    Read-Host "Enter para continuar..."
}

function Verificar-Estado-Servicios {
    Clear-Host
    Log-Aviso "--- ESTADO DE LOS SERVICIOS ---"
    foreach ($s in @("DhcpServer", "DNS")) {
        $status = Get-Service -Name $s -ErrorAction SilentlyContinue
        Write-Host "  $s : " -NoNewline
        if ($status -and $status.Status -eq "Running") {
            Write-Host "[CORRIENDO]" -ForegroundColor Green
        } else {
            Write-Host "[DETENIDO/NO INSTALADO]" -ForegroundColor Red
        }
    }
    Read-Host "Enter para continuar..."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 3 — SSH
# ────────────────────────────────────────────────────────────

function SSH-Instalar-Configurar {
    Write-Host ""
    Log-Aviso "--- INSTALANDO SSH SERVER EN WINDOWS ---"

    $capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($null -eq $capability) {
        Log-Error "No se encontro la caracteristica OpenSSH.Server."
        return
    }

    if ($capability.State -eq 'Installed') {
        Log-Aviso "OpenSSH Server ya esta instalado."
    } else {
        Log-Aviso "Instalando OpenSSH Server..."
        Add-WindowsCapability -Online -Name $capability.Name | Out-Null
        Log-Exito "OpenSSH Server instalado."
    }

    try {
        Set-Service   -Name sshd -StartupType Automatic
        Start-Service -Name sshd
        Log-Exito "Servicio sshd iniciado en modo automatico."
    } catch {
        Log-Error "No se pudo iniciar el servicio sshd: $_"
        return
    }

    if (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue) {
        Log-Aviso "Regla de Firewall ya existe."
    } else {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
            -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
        Log-Exito "Regla de Firewall creada: puerto 22 permitido."
    }

    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -First 1 -ExpandProperty IPAddress)
    Log-Exito "SSH listo. Conectate con: ssh $env:USERNAME@$ip"
}

function SSH-Verificar-Instalacion {
    Write-Host ""
    Log-Aviso "=== Verificando SSH Server en Windows ==="

    $capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($capability -and $capability.State -eq 'Installed') {
        Log-Exito "OpenSSH Server esta instalado."
    } else {
        Log-Error "OpenSSH Server NO esta instalado."
    }

    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Log-Exito "Servicio sshd esta corriendo."
    } else {
        Log-Warn "Servicio sshd esta INACTIVO."
    }

    if (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue) {
        Log-Exito "Firewall permite SSH (puerto 22)."
    } else {
        Log-Warn "Firewall NO tiene SSH permitido."
    }

    Write-Host ""
    Log-Aviso "IP de esta maquina:"
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -ExpandProperty IPAddress | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
}

function SSH-Conectarse {
    Write-Host ""
    Log-Aviso "=== Conexion SSH a servidor remoto ==="

    $ipLocal = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -First 1 -ExpandProperty IPAddress)
    Log-Aviso "Tu IP actual: $ipLocal"
    Write-Host ""

    $ip = Pedir-IP-Segura "IP del servidor remoto"

    Log-Aviso "Verificando conectividad con $ip ..."
    if (-not (Test-Connection -ComputerName $ip -Count 2 -Quiet -ErrorAction SilentlyContinue)) {
        Log-Warn "$ip no responde al ping."
        $resp = Read-Host "Intentar conectarse de todos modos? (s/n)"
        if ($resp -ne "s") { return }
    } else {
        Log-Exito "$ip responde. Red OK."
    }

    $user = ""
    while ([string]::IsNullOrWhiteSpace($user)) {
        $user = Read-Host "Usuario en $ip"
        if ([string]::IsNullOrWhiteSpace($user)) { Log-Error "El usuario no puede estar vacio." }
    }

    Write-Host ""
    Log-Aviso "Conectando a $user@$ip ..."
    Write-Host "(Para cerrar la sesion escribe: exit)" -ForegroundColor Yellow
    Write-Host ""

    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$user@$ip"

    Write-Host ""
    Log-Exito "Sesion cerrada. De vuelta en $env:COMPUTERNAME ($ipLocal)."
}
