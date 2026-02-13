function Validar-IP {
    param([string]$ip)

    if ([string]::IsNullOrWhiteSpace($ip)) { return $false }
    if (-not ($ip -match '^([0-9]{1,3}\.){3}[0-9]{1,3}$')) { return $false }

    foreach ($o in $ip.Split('.')) {
        if ([int]$o -gt 255) { return $false }
    }
    return $true
}

function IP-a-Entero {
    param([string]$ip)
    $o = $ip.Split('.')
    return ([int]$o[0] -shl 24) -bor
           ([int]$o[1] -shl 16) -bor
           ([int]$o[2] -shl 8)  -bor
           ([int]$o[3])
}

function Entero-a-IP {
    param([int]$n)
    return "$(($n -shr 24) -band 255).$((($n -shr 16) -band 255)).$((($n -shr 8) -band 255)).$($n -band 255)"
}

function Siguiente-IP {
    param([string]$ip)
    return Entero-a-IP ((IP-a-Entero $ip) + 1)
}

function Calcular-Mascara24 {
    return "255.255.255.0"
}



function Configurar-IPServidor {
    param([string]$ip)

    $mask = Calcular-Mascara24
    $prefix = 24

    $adapter = Get-NetAdapter -Name "Ethernet" -ErrorAction SilentlyContinue
    if (-not $adapter) {
        Write-Host "No se encontro interfaz Ethernet"
        return
    }

    Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false

    New-NetIPAddress `
        -IPAddress $ip `
        -PrefixLength $prefix `
        -InterfaceIndex $adapter.InterfaceIndex

    Write-Host "Servidor configurado con IP $ip"
}



function DHCP-Instalado {
    (Get-WindowsFeature DHCP).Installed
}

function Verificar-EstadoServicio {

    Write-Host ""
    Write-Host "=== ESTADO DEL SERVICIO DHCP ==="

    if (DHCP-Instalado) {
        Write-Host "Servicio DHCP: INSTALADO"

        $serv = Get-Service DHCPServer -ErrorAction SilentlyContinue
        if ($serv.Status -eq "Running") {
            Write-Host "Estado: EN EJECUCION"
        }
        else {
            Write-Host "Estado: DETENIDO"
        }
    }
    else {
        Write-Host "Servicio DHCP: NO INSTALADO"
    }
}

function Instalar-DHCP {

    if (DHCP-Instalado) {

        do {
            $r = Read-Host "Servicio ya instalado ¿Desea volver a instalarlo? (y/n)"
        } until ($r -in @("y","n"))

        if ($r -eq "n") { return }

        Uninstall-WindowsFeature DHCP -IncludeManagementTools | Out-Null
        Restart-Computer -Force
        return
    }

    Install-WindowsFeature DHCP -IncludeManagementTools | Out-Null
    Add-DhcpServerInDC | Out-Null
    Write-Host "DHCP instalado correctamente"
}

function Limpiar-ScopesDHCP {
    Get-DhcpServerv4Scope -ErrorAction SilentlyContinue |
    Remove-DhcpServerv4Scope -Force -ErrorAction SilentlyContinue
}

function Forzar-InterfazDHCP {
    $bindings = Get-DhcpServerv4Binding
    foreach ($b in $bindings) {
        Set-DhcpServerv4Binding `
            -InterfaceAlias $b.InterfaceAlias `
            -BindingState ($b.InterfaceAlias -eq "Ethernet")
    }
    Restart-Service DHCPServer
}



function Configurar-DHCP {

    if (-not (DHCP-Instalado)) {
        Write-Host "DHCP no instalado"
        return
    }

    Limpiar-ScopesDHCP

    $scope = Read-Host "Nombre del ambito"

    do { $start = Read-Host "IP inicial (sera del servidor)" }
    until (Validar-IP $start)

    do { $end = Read-Host "IP final" }
    until (Validar-IP $end)

    $poolStart = Siguiente-IP $start
    $mask = Calcular-Mascara24

    Configurar-IPServidor $start
    Forzar-InterfazDHCP

    $scopeObj = Add-DhcpServerv4Scope `
        -Name $scope `
        -StartRange $poolStart `
        -EndRange $end `
        -SubnetMask $mask `
        -State Active

    $gateway = Read-Host "Gateway (opcional)"
    if (Validar-IP $gateway) {
        Set-DhcpServerv4OptionValue -ScopeId $scopeObj.ScopeId -Router $gateway
    }

    $dns = Read-Host "DNS (opcional)"
    if (Validar-IP $dns) {
        Set-DhcpServerv4OptionValue -ScopeId $scopeObj.ScopeId -DnsServer $dns
    }

    Write-Host ""
    Write-Host "DHCP configurado correctamente"
    Write-Host "Servidor:" $start
    Write-Host "Pool desde:" $poolStart
}



function Monitoreo-DHCP {

    if (-not (DHCP-Instalado)) {
        Write-Host "DHCP no instalado"
        return
    }

    Write-Host "CTRL + C para salir"

    while ($true) {
        Clear-Host

        Get-Service DHCPServer
        Write-Host ""

        $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue

        foreach ($s in $scopes) {
            Write-Host "Ambito:" $s.Name
            Get-DhcpServerv4Lease -ScopeId $s.ScopeId -ErrorAction SilentlyContinue
            Write-Host ""
        }

        Start-Sleep 5
    }
}



function Menu {
    do {
        Write-Host ""
        Write-Host "===== DHCP WINDOWS SERVER 2022 ====="
        Write-Host "1. Instalar DHCP"
        Write-Host "2. Configurar DHCP"
        Write-Host "3. Monitorear"
        Write-Host "4. Ver estado del servicio"
        Write-Host "5. Salir"

        $op = Read-Host "Seleccione opcion"

        if ($op -eq "1") { Instalar-DHCP }
        elseif ($op -eq "2") { Configurar-DHCP }
        elseif ($op -eq "3") { Monitoreo-DHCP }
        elseif ($op -eq "4") { Verificar-EstadoServicio }

    } while ($op -ne "5")
}

Menu
