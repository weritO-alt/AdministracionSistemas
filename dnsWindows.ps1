# ============================================================
#   GESTOR UNIFICADO - DHCP + DNS - WINDOWS SERVER
#   Version 2.0 - Mejorado
# ============================================================

# ---------------------------------------------------
# 1. FUNCIONES DE LOG Y VALIDACION
# ---------------------------------------------------

function Log-Exito { param([string]$texto); Write-Host "[OK]    $texto" -ForegroundColor Green }
function Log-Error { param([string]$texto); Write-Host "[ERROR] $texto" -ForegroundColor Red }
function Log-Aviso { param([string]$texto); Write-Host "[INFO]  $texto" -ForegroundColor Cyan }
function Log-Warn  { param([string]$texto); Write-Host "[WARN]  $texto" -ForegroundColor Yellow }

function Verificar-Admin {
    $identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identidad)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Log-Error "Necesitas correr este script como ADMINISTRADOR."
        Start-Sleep -Seconds 3
        exit
    }
}

function Pedir-Entero {
    param (
        [string]$Mensaje,
        [string]$Ayuda = ""
    )
    if ($Ayuda -ne "") { Log-Aviso $Ayuda }
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
    param ([int]$Prefijo)
    if ($Prefijo -lt 1 -or $Prefijo -gt 30) {
        Log-Error "Prefijo invalido. Debe estar entre 1 y 30."
        return $null
    }
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

# Calcula la Network ID correctamente segun el prefijo, no asume /24
function Obtener-NetworkID {
    param ([string]$IP, [int]$Prefijo)
    $ipObj = [IPAddress]$IP
    $ipBytes = $ipObj.GetAddressBytes()
    $mascara = [uint32]::MaxValue -shl (32 - $Prefijo)
    $mascaraBytes = [BitConverter]::GetBytes([uint32][IPAddress]::HostToNetworkOrder($mascara))
    $netBytes = for ($i = 0; $i -lt 4; $i++) { $ipBytes[$i] -band $mascaraBytes[$i] }
    return ($netBytes -join ".")
}

function Pedir-IP-Segura {
    param ([string]$Mensaje, [bool]$EsOpcional = $false)
    while ($true) {
        $entrada = (Read-Host "$Mensaje").Trim()
        if ($EsOpcional -and $entrada -eq "") { return "" }
        if ($entrada -eq "") { Log-Error "No lo dejes vacio."; continue }

        if ($entrada -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            if ($entrada -in @("0.0.0.0", "127.0.0.1", "255.255.255.255")) {
                Log-Error "IP $entrada NO permitida (reservada)."
            } else { return $entrada }
        } else { Log-Error "Formato incorrecto. Usa X.X.X.X (0-255)." }
    }
}

function Pedir-Tiempo-Lease {
    Log-Aviso "Ejemplos: 3600=1hr | 86400=1dia | 604800=1semana"
    return Pedir-Entero "Tiempo de Lease en segundos"
}

# ---------------------------------------------------
# 2. INSTALACION GENERICA DE ROLES
# ---------------------------------------------------

function Instalar-Rol {
    param ([string]$Rol)
    Log-Aviso "Verificando rol $Rol..."
    if ((Get-WindowsFeature $Rol).Installed) {
        Log-Exito "$Rol ya esta instalado."
    } else {
        try {
            Install-WindowsFeature -Name $Rol -IncludeManagementTools -ErrorAction Stop | Out-Null
            Import-Module $Rol -ErrorAction SilentlyContinue
            Start-Service $Rol -ErrorAction SilentlyContinue
            Log-Exito "$Rol instalado y corriendo."
        } catch {
            Log-Error "Fallo al instalar $Rol : $_"
        }
    }
    Read-Host "Enter para continuar..."
}

function Desinstalar-Rol {
    param ([string]$Rol)
    if (-not (Get-WindowsFeature $Rol).Installed) {
        Log-Warn "$Rol no esta instalado, nada que desinstalar."
    } else {
        try {
            Uninstall-WindowsFeature -Name $Rol -Remove -ErrorAction Stop | Out-Null
            Log-Exito "$Rol desinstalado correctamente."
        } catch {
            Log-Error "Fallo al desinstalar $Rol : $_"
        }
    }
    Read-Host "Enter para continuar..."
}

# ---------------------------------------------------
# 3. MODULO DHCP
# ---------------------------------------------------

function Configurar-Todo-Scope {
    Clear-Host
    Log-Aviso "--- CONFIGURACION DE RED Y SCOPE (DHCP + DNS) ---"
    Get-NetAdapter | Select-Object Name, Status, LinkSpeed | Format-Table -AutoSize

    $NombreInterfaz = Read-Host "Nombre del adaptador [Default: Ethernet 2]"
    if ($NombreInterfaz -eq "") { $NombreInterfaz = "Ethernet 2" }

    if (-not (Get-NetAdapter -Name $NombreInterfaz -ErrorAction SilentlyContinue)) {
        Log-Error "No existe el adaptador '$NombreInterfaz'. Verifica el nombre."
        Read-Host "Enter para continuar..."
        return
    }

    $RangoInicio = Pedir-IP-Segura "1. IP Inicio del Rango (sera la IP del servidor)"
    
    while ($true) {
        $RangoFin = Pedir-IP-Segura "2. IP Fin del Rango"
        if ([Version]$RangoFin -gt [Version]$RangoInicio) { break }
        Log-Error "La IP Final debe ser mayor a $RangoInicio."
    }

    while ($true) {
        $Prefijo = Read-Host "3. Prefijo CIDR (1-30) [Default: 24]"
        if ($Prefijo -eq "") { $Prefijo = 24; break }
        if ($Prefijo -match '^\d+$' -and [int]$Prefijo -ge 1 -and [int]$Prefijo -le 30) { $Prefijo = [int]$Prefijo; break }
        Log-Error "Prefijo invalido. Ingresa un numero entre 1 y 30."
    }
    $Mascara = Obtener-Mascara-Desde-Prefijo $Prefijo

    $Gateway   = Pedir-IP-Segura "4. Gateway (Enter para omitir)" $true
    $DnsServer = Pedir-IP-Segura "5. Servidor DNS (recomendado: IP de este servidor)"

    $NombreScope = ""
    while ($NombreScope -eq "") {
        $NombreScope = (Read-Host "6. Nombre del Scope").Trim()
        if ($NombreScope -eq "") { Log-Error "El nombre del scope no puede estar vacio." }
    }

    $TiempoLease = Pedir-Tiempo-Lease
    $NetworkID   = Obtener-NetworkID -IP $RangoInicio -Prefijo $Prefijo

    # --- Configurar IP estatica en la interfaz ---
    Log-Aviso "Configurando IP estatica en '$NombreInterfaz'..."
    try {
        Remove-NetIPAddress -InterfaceAlias $NombreInterfaz -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceAlias $NombreInterfaz -Confirm:$false -ErrorAction SilentlyContinue

        $params = @{
            InterfaceAlias = $NombreInterfaz
            IPAddress      = $RangoInicio
            PrefixLength   = $Prefijo
            ErrorAction    = "Stop"
        }
        if ($Gateway -ne "") { $params["DefaultGateway"] = $Gateway }
        New-NetIPAddress @params | Out-Null
        Log-Exito "IP $RangoInicio/$Prefijo asignada a $NombreInterfaz."
    } catch {
        Log-Error "Error configurando IP estatica: $_"
        Read-Host "Enter para continuar..."
        return
    }

    # --- Crear o reemplazar Scope DHCP ---
    if (Get-DhcpServerv4Scope -ScopeId $NetworkID -ErrorAction SilentlyContinue) {
        Log-Warn "Ya existe un scope con NetworkID $NetworkID. Se reemplazara."
        Remove-DhcpServerv4Scope -ScopeId $NetworkID -Force
    }

    try {
        Add-DhcpServerv4Scope -Name $NombreScope -StartRange $RangoInicio -EndRange $RangoFin `
            -SubnetMask $Mascara -State Active -ErrorAction Stop

        Set-DhcpServerv4Scope -ScopeId $NetworkID `
            -LeaseDuration (New-TimeSpan -Seconds $TiempoLease) -ErrorAction Stop

        if ($Gateway -ne "") {
            Set-DhcpServerv4OptionValue -ScopeId $NetworkID -OptionId 3 -Value $Gateway -Force
        }
        Set-DhcpServerv4OptionValue -ScopeId $NetworkID -OptionId 6 -Value $DnsServer -Force

        Restart-Service DhcpServer -Force
        Log-Exito "Scope '$NombreScope' configurado correctamente."
        Log-Exito "  Rango  : $RangoInicio - $RangoFin"
        Log-Exito "  Mascara: $Mascara"
        Log-Exito "  DNS    : $DnsServer"
        if ($Gateway) { Log-Exito "  Gateway: $Gateway" }
        Log-Exito "  Lease  : $TiempoLease segundos"
    } catch {
        Log-Error "Fallo configurando el Scope: $_"
    }

    Read-Host "Enter para continuar..."
}

function Monitorear-Clientes {
    Clear-Host
    Log-Aviso "--- CLIENTES CONECTADOS (Leases activos) ---"

    try {
        $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
        if (-not $scopes) {
            Log-Warn "No hay scopes configurados."
            Read-Host "Enter para continuar..."
            return
        }

        $totalLeases = 0
        foreach ($scope in $scopes) {
            $leases = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
            if ($leases) {
                Write-Host "`nScope: $($scope.Name) [$($scope.ScopeId)]" -ForegroundColor Yellow
                $leases | Select-Object IPAddress, HostName, ClientId, LeaseExpiryTime, AddressState | Format-Table -AutoSize
                $totalLeases += $leases.Count
            }
        }

        if ($totalLeases -eq 0) { Log-Warn "No hay leases activos en ningun scope." }
        else { Log-Exito "Total de leases activos: $totalLeases" }

    } catch {
        Log-Error "Error obteniendo leases: $_"
    }

    Read-Host "Enter para continuar..."
}

function Editar-Scope {
    Clear-Host
    Log-Aviso "--- EDITAR SCOPE EXISTENTE ---"

    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if (-not $scopes) { Log-Warn "No hay scopes configurados."; Read-Host "Enter..."; return }

    Write-Host "`nScopes disponibles:" -ForegroundColor Yellow
    $scopes | Select-Object Name, ScopeId, StartRange, EndRange, LeaseDuration | Format-Table -AutoSize

    $scopeId = (Read-Host "Ingresa el ScopeId a editar (ej. 192.168.1.0)").Trim()
    $scope = Get-DhcpServerv4Scope -ScopeId $scopeId -ErrorAction SilentlyContinue
    if (-not $scope) { Log-Error "Scope no encontrado."; Read-Host "Enter..."; return }

    Log-Aviso "Deja vacio para conservar el valor actual."

    $nuevoNombre = (Read-Host "Nuevo nombre [$($scope.Name)]").Trim()
    if ($nuevoNombre -ne "") { Set-DhcpServerv4Scope -ScopeId $scopeId -Name $nuevoNombre }

    $nuevoLease = Read-Host "Nuevo Lease en segundos (actual: $($scope.LeaseDuration.TotalSeconds))"
    if ($nuevoLease -match '^\d+$' -and [int]$nuevoLease -gt 0) {
        Set-DhcpServerv4Scope -ScopeId $scopeId -LeaseDuration (New-TimeSpan -Seconds ([int]$nuevoLease))
    }

    $nuevoDns = Read-Host "Nuevo DNS (Enter para omitir)"
    if ($nuevoDns -ne "") { Set-DhcpServerv4OptionValue -ScopeId $scopeId -OptionId 6 -Value $nuevoDns -Force }

    $nuevoGw = Read-Host "Nuevo Gateway (Enter para omitir)"
    if ($nuevoGw -ne "") { Set-DhcpServerv4OptionValue -ScopeId $scopeId -OptionId 3 -Value $nuevoGw -Force }

    Restart-Service DhcpServer -Force
    Log-Exito "Scope actualizado correctamente."
    Read-Host "Enter para continuar..."
}

# ---------------------------------------------------
# 4. MODULO DNS
# ---------------------------------------------------

function Agregar-Dominio-DNS {
    Clear-Host
    Log-Aviso "--- AGREGAR DOMINIO DNS ---"

    $dominio = (Read-Host "Nombre del dominio (ej. empresa.com)").Trim()
    if ($dominio -eq "") { Log-Error "El dominio no puede estar vacio."; Read-Host "Enter..."; return }

    if (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue) {
        Log-Warn "El dominio '$dominio' ya existe."
        Read-Host "Enter para continuar..."
        return
    }

    $ip = Pedir-IP-Segura "IP asociada a este dominio"

    try {
        Add-DnsServerPrimaryZone -Name $dominio -ZoneFile "$dominio.dns" -ErrorAction Stop
        Add-DnsServerResourceRecordA    -Name "@"   -ZoneName $dominio -IPv4Address $ip -ErrorAction Stop
        Add-DnsServerResourceRecordA    -Name "ns1" -ZoneName $dominio -IPv4Address $ip -ErrorAction Stop
        Add-DnsServerResourceRecordCName -Name "www" -HostNameAlias "$dominio." -ZoneName $dominio -ErrorAction Stop
        Log-Exito "Dominio '$dominio' creado con registros A (@, ns1) y CNAME (www)."
    } catch {
        Log-Error "Fallo al crear el dominio: $_"
    }

    Read-Host "Enter para continuar..."
}

function Eliminar-Dominio-DNS {
    Clear-Host
    Log-Aviso "--- ELIMINAR DOMINIO DNS ---"

    $zonas = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }
    if (-not $zonas) { Log-Warn "No hay dominios para eliminar."; Read-Host "Enter..."; return }

    Write-Host "`nDominios disponibles:" -ForegroundColor Yellow
    foreach ($z in $zonas) { Write-Host "  - $($z.ZoneName)" }

    $dominio = (Read-Host "`nDominio a eliminar").Trim()
    if ($dominio -eq "") { return }

    if (-not (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue)) {
        Log-Error "El dominio '$dominio' no existe."
    } else {
        $confirm = Read-Host "Seguro? Esto elimina TODOS los registros de '$dominio'. (s/n)"
        if ($confirm -eq "s") {
            Remove-DnsServerZone -Name $dominio -Force
            Log-Exito "Dominio '$dominio' eliminado."
        } else {
            Log-Aviso "Operacion cancelada."
        }
    }
    Read-Host "Enter para continuar..."
}

function Listar-Dominios-DNS {
    Clear-Host
    Log-Aviso "--- DOMINIOS DNS ACTIVOS ---"

    $zonas = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }

    if (-not $zonas) { Log-Warn "No hay dominios configurados."; Read-Host "Enter..."; return }

    foreach ($z in $zonas) {
        $record = Get-DnsServerResourceRecord -ZoneName $z.ZoneName -RRType A -ErrorAction SilentlyContinue |
                  Where-Object { $_.HostName -eq "@" } | Select-Object -First 1
        $ip = if ($record) { $record.RecordData.IPv4Address } else { "(Sin registro A)" }
        Write-Host "  $($z.ZoneName.PadRight(30)) -> $ip"
    }

    Read-Host "`nEnter para continuar..."
}

function Editar-Registros-DNS {
    Clear-Host
    Log-Aviso "--- EDITAR REGISTROS DE UN DOMINIO ---"

    $zonas = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }
    if (-not $zonas) { Log-Warn "No hay dominios."; Read-Host "Enter..."; return }

    foreach ($z in $zonas) { Write-Host "  - $($z.ZoneName)" }
    $dominio = (Read-Host "`nDominio a editar").Trim()

    if (-not (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue)) {
        Log-Error "Dominio no encontrado."
        Read-Host "Enter..."
        return
    }

    Write-Host "`nRegistros actuales:" -ForegroundColor Yellow
    Get-DnsServerResourceRecord -ZoneName $dominio | Select-Object HostName, RecordType, RecordData | Format-Table -AutoSize

    Write-Host "1. Agregar registro A`n2. Agregar registro CNAME`n3. Eliminar registro"
    $op = Read-Host "Opcion"

    switch ($op) {
        "1" {
            $host_ = Read-Host "Nombre del host (@ para raiz)"
            $ip    = Pedir-IP-Segura "IP"
            Add-DnsServerResourceRecordA -Name $host_ -ZoneName $dominio -IPv4Address $ip
            Log-Exito "Registro A agregado."
        }
        "2" {
            $alias  = Read-Host "Alias (nombre del CNAME)"
            $target = Read-Host "Apunta a (ej. empresa.com.)"
            Add-DnsServerResourceRecordCName -Name $alias -HostNameAlias $target -ZoneName $dominio
            Log-Exito "CNAME agregado."
        }
        "3" {
            $host_ = Read-Host "Nombre del host a eliminar"
            $tipo  = Read-Host "Tipo de registro (A, CNAME, etc.)"
            Remove-DnsServerResourceRecord -ZoneName $dominio -Name $host_ -RRType $tipo -Force
            Log-Exito "Registro eliminado."
        }
        default { Log-Warn "Opcion no valida." }
    }

    Read-Host "Enter para continuar..."
}

# ---------------------------------------------------
# 5. ESTADO DE SERVICIOS
# ---------------------------------------------------

function Verificar-Estado-Servicio {
    Clear-Host
    Log-Aviso "--- ESTADO DE SERVICIOS Y CONFIGURACION ---"

    $servicios = @(
        @{ Nombre = "DhcpServer"; Display = "DHCP Server" },
        @{ Nombre = "DNS";        Display = "DNS Server"  }
    )

    foreach ($s in $servicios) {
        $instalado = (Get-WindowsFeature $s.Nombre -ErrorAction SilentlyContinue).Installed
        $status    = Get-Service -Name $s.Nombre -ErrorAction SilentlyContinue

        $estadoStr = if (-not $instalado)                    { "[NO INSTALADO]" }
                     elseif ($status.Status -eq "Running")   { "[CORRIENDO]    " }
                     else                                     { "[DETENIDO]     " }

        $color = if ($status.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "$($s.Display.PadRight(15)) : " -NoNewline
        Write-Host $estadoStr -ForegroundColor $color
    }

    Write-Host ""
    Log-Aviso "Scopes DHCP activos:"
    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if ($scopes) { $scopes | Select-Object Name, ScopeId, StartRange, EndRange | Format-Table -AutoSize }
    else         { Write-Host "  Ninguno" }

    Log-Aviso "Dominios DNS activos:"
    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }
    if ($zonas) { $zonas | Select-Object ZoneName, ZoneType | Format-Table -AutoSize }
    else        { Write-Host "  Ninguno" }

    Read-Host "Enter para continuar..."
}

# ---------------------------------------------------
# 6. MENUS
# ---------------------------------------------------

function SubMenu-DHCP {
    while ($true) {
        Clear-Host
        $dhcpInstalado = (Get-WindowsFeature DHCP -ErrorAction SilentlyContinue).Installed
        $estadoDHCP    = if ($dhcpInstalado) { "[INSTALADO]" } else { "[NO INSTALADO]" }

        Write-Host "--- SUBMENU DHCP $estadoDHCP ---" -ForegroundColor Yellow
        Write-Host "1. Instalar DHCP"
        Write-Host "2. Configurar Scope"
        Write-Host "3. Editar Scope existente"
        Write-Host "4. Ver clientes conectados"
        Write-Host "5. Desinstalar DHCP"
        Write-Host "6. Volver al menu principal"

        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { Instalar-Rol "DHCP" }
            "2" { Configurar-Todo-Scope }
            "3" { Editar-Scope }
            "4" { Monitorear-Clientes }
            "5" { Desinstalar-Rol "DHCP" }
            "6" { return }
            default { Log-Warn "Opcion '$op' no valida. Elige entre 1 y 6."; Start-Sleep -Seconds 1 }
        }
    }
}

function SubMenu-DNS {
    while ($true) {
        Clear-Host
        $dnsInstalado = (Get-WindowsFeature DNS -ErrorAction SilentlyContinue).Installed
        $estadoDNS    = if ($dnsInstalado) { "[INSTALADO]" } else { "[NO INSTALADO]" }

        Write-Host "--- SUBMENU DNS $estadoDNS ---" -ForegroundColor Green
        Write-Host "1. Instalar DNS"
        Write-Host "2. Agregar Dominio"
        Write-Host "3. Listar Dominios"
        Write-Host "4. Editar registros de un Dominio"
        Write-Host "5. Eliminar Dominio"
        Write-Host "6. Desinstalar DNS"
        Write-Host "7. Volver al menu principal"

        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { Instalar-Rol "DNS" }
            "2" { Agregar-Dominio-DNS }
            "3" { Listar-Dominios-DNS }
            "4" { Editar-Registros-DNS }
            "5" { Eliminar-Dominio-DNS }
            "6" { Desinstalar-Rol "DNS" }
            "7" { return }
            default { Log-Warn "Opcion '$op' no valida. Elige entre 1 y 7."; Start-Sleep -Seconds 1 }
        }
    }
}

# ---------------------------------------------------
# 7. PUNTO DE ENTRADA
# ---------------------------------------------------

Verificar-Admin

while ($true) {
    Clear-Host

    $dhcpStatus = if ((Get-WindowsFeature DHCP -EA SilentlyContinue).Installed)  { "ON" } else { "OFF" }
    $dnsStatus  = if ((Get-WindowsFeature DNS  -EA SilentlyContinue).Installed)  { "ON" } else { "OFF" }

    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   GESTOR UNIFICADO - WINDOWS SERVER" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   DHCP: " -NoNewline
    Write-Host $dhcpStatus.PadRight(5) -ForegroundColor (if ($dhcpStatus -eq "ON") {"Green"} else {"Red"}) -NoNewline
    Write-Host "   DNS: " -NoNewline
    Write-Host $dnsStatus -ForegroundColor (if ($dnsStatus -eq "ON") {"Green"} else {"Red"})
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Administrar DHCP"
    Write-Host "2. Administrar DNS"
    Write-Host "3. Ver estado general"
    Write-Host "4. Salir"
    Write-Host ""

    $op = Read-Host "Opcion"
    switch ($op) {
        "1" { SubMenu-DHCP }
        "2" { SubMenu-DNS }
        "3" { Verificar-Estado-Servicio }
        "4" { exit }
        default { Log-Warn "Opcion '$op' no valida. Elige entre 1 y 4."; Start-Sleep -Seconds 1 }
    }
}
