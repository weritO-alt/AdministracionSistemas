# ---------------------------------------------------

# 1. MIS FUNCIONES PARA MENSAJES Y VALIDACIONES

# ---------------------------------------------------



function Log-Exito { param([string]$texto); Write-Host "[OK] $texto" -ForegroundColor Green }

function Log-Error { param([string]$texto); Write-Host "[ERROR] $texto" -ForegroundColor Red }

function Log-Aviso { param([string]$texto); Write-Host "[INFO] $texto" -ForegroundColor Cyan }



function Verificar-Admin {

    $identidad = [Security.Principal.WindowsIdentity]::GetCurrent()

    $principal = New-Object Security.Principal.WindowsPrincipal($identidad)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

        Log-Error "Ocupas correr VS Code o PowerShell como ADMINISTRADOR."

        Start-Sleep -Seconds 5; exit

    }

}



function Pedir-Entero {

    param ([string]$Mensaje)

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



function Pedir-IP-Segura {

    param ([string]$Mensaje, [string]$EsOpcional = "no")

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



# ---------------------------------------------------

# 2. MODULO DHCP

# ---------------------------------------------------



function Instalar-Rol-DHCP {

    Log-Aviso "Verificando DHCP..."

    if ((Get-WindowsFeature DHCP).Installed) { Log-Exito "DHCP ya instalado." }

    else {

        Install-WindowsFeature DHCP -IncludeManagementTools

        Log-Exito "Instalacion completa."

    }

    Read-Host "Enter para continuar..."

}



function Configurar-Todo-Scope {

    Log-Aviso "--- CONFIGURACION DE RED Y SCOPE (DHCP + DNS) ---"

    Get-NetAdapter | Select-Object Name, Status | Format-Table -AutoSize

    $NombreInterfaz = Read-Host "Nombre del adaptador [Default: Ethernet 2]"

    if ($NombreInterfaz -eq "") { $NombreInterfaz = "Ethernet 2" }



    $RangoInicio = Pedir-IP-Segura "1. IP Inicio Rango (Server IP)"

    

    while ($true) {

        $RangoFin = Pedir-IP-Segura "2. IP Fin Rango"

        if ([Version]$RangoFin -gt [Version]$RangoInicio) { break }

        else { Log-Error "La IP Final debe ser mayor a $RangoInicio." }

    }



    $Prefijo = Read-Host "3. Prefijo (24, 16, 8) [Default: 24]"

    if ($Prefijo -eq "") { $Prefijo = 24 }

    $Mascara = Obtener-Mascara-Desde-Prefijo ([int]$Prefijo)

    

    $Gateway = Pedir-IP-Segura "4. Gateway (Enter para omitir)" "si"

    $DnsServer = Pedir-IP-Segura "5. DNS (Recomendado: La IP de este servidor)"

    

    $NombreScope = Read-Host "6. Nombre del Scope"

    $TiempoLease = Pedir-Entero "7. Tiempo Lease (segundos)"



    Log-Aviso "Configurando IP Estatica en la interfaz..."

    try {

        Remove-NetIPAddress -InterfaceAlias $NombreInterfaz -Confirm:$false -ErrorAction SilentlyContinue

        if ($Gateway) {

            New-NetIPAddress -InterfaceAlias $NombreInterfaz -IPAddress $RangoInicio -PrefixLength $Prefijo -DefaultGateway $Gateway -ErrorAction SilentlyContinue

        } else {

            New-NetIPAddress -InterfaceAlias $NombreInterfaz -IPAddress $RangoInicio -PrefixLength $Prefijo -ErrorAction SilentlyContinue

        }

    } catch { Log-Error "Error en IP fija." }

    

    $partes = $RangoInicio.Split("."); $netID = "$($partes[0]).$($partes[1]).$($partes[2]).0"

    

    if (Get-DhcpServerv4Scope -ScopeId $netID -ErrorAction SilentlyContinue) { 

        Remove-DhcpServerv4Scope -ScopeId $netID -Force 

    }

    

    try {

        Add-DhcpServerv4Scope -Name $NombreScope -StartRange $RangoInicio -EndRange $RangoFin -SubnetMask $Mascara -State Active

        Set-DhcpServerv4Scope -ScopeId $netID -LeaseDuration (New-TimeSpan -Seconds $TiempoLease)

        

        if ($Gateway) { Set-DhcpServerv4OptionValue -ScopeId $netID -OptionId 3 -Value $Gateway }

        

        Log-Aviso "Vinculando Servidor DNS $DnsServer al Scope..."

        Set-DhcpServerv4OptionValue -ScopeId $netID -OptionId 6 -Value $DnsServer -Force

        

        Log-Exito "DNS vinculado correctamente al ambito DHCP."

    } catch {

        Log-Error "Fallo en la configuracion del Scope: $_"

    }



    Restart-Service DhcpServer -Force

    Log-Exito "Configuracion terminada al 100%."

    Read-Host "Enter para continuar..."

}



function Monitorear-Clientes {

    Log-Aviso "CLIENTES CONECTADOS (Leases)"

    Get-DhcpServerv4Lease -ScopeId 0.0.0.0 -ErrorAction SilentlyContinue | Select-Object IPAddress, HostName, LeaseExpiryTime | Format-Table -AutoSize

    Read-Host "Enter para continuar..."

}



# ---------------------------------------------------

# 3. MODULO DNS

# ---------------------------------------------------



function Instalar-DNS {
    Clear-Host
    Log-Aviso "--- INSTALACION DE DNS ---"
    Log-Aviso "Instalando el rol de DNS y sus herramientas..."
    
    # Instalacion limpia y nativa (No pide reinicio en un server limpio)
    Install-WindowsFeature -Name DNS -IncludeManagementTools | Out-Null
    
    # Le decimos a PowerShell que reconozca los comandos en este milisegundo
    Import-Module DnsServer -ErrorAction SilentlyContinue
    
    # Aseguramos que el motor este encendido
    Start-Service DNS -ErrorAction SilentlyContinue
    
    Log-Exito "DNS Instalado y corriendo al 100% sin necesidad de reiniciar."
    Read-Host "Enter para continuar..."
}


function Agregar-Dominio-DNS {

    Log-Aviso "--- GESTOR ABC: AGREGAR DOMINIO ---"

    $dominio = Read-Host "Nombre del dominio (ej. reprobados.com)"

    if (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue) { Log-Aviso "Ya existe."; return }



    $ip = Pedir-IP-Segura "IP para este dominio"

    Add-DnsServerPrimaryZone -Name $dominio -ZoneFile "$dominio.dns"

    Add-DnsServerResourceRecordA -Name "@" -ZoneName $dominio -IPv4Address $ip

    Add-DnsServerResourceRecordA -Name "ns1" -ZoneName $dominio -IPv4Address $ip

    Add-DnsServerResourceRecordCName -Name "www" -HostNameAlias "$dominio." -ZoneName $dominio

    Log-Exito "Dominio y registros creados."

    Read-Host "Enter..."

}

function Eliminar-Dominio-DNS {
    Log-Aviso "--- GESTOR ABC: ELIMINAR DOMINIO ---"
    
    # Listamos los dominios primero para que veas que puedes borrar
    $zonas = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }
    
    if (-not $zonas) { 
        Log-Aviso "No hay dominios activos para eliminar."
        Read-Host "Enter para continuar..."
        return 
    }
    
    Log-Aviso "Dominios disponibles:"
    foreach ($z in $zonas) { Write-Host "- $($z.ZoneName)" -ForegroundColor White }
    
    $dominio = Read-Host "`nIngresa el nombre exacto del dominio a eliminar (ej. reprobados.com)"
    if ($dominio -eq "") { return }

    if (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue) {
        Remove-DnsServerZone -Name $dominio -Force
        Log-Exito "Dominio $dominio y todos sus registros fueron eliminados."
    } else {
        Log-Error "Ese dominio no existe en el servidor."
    }
    Read-Host "Enter para continuar..."
}


function Listar-Dominios-DNS {

    Log-Aviso "--- DOMINIOS ACTIVOS ---"

    $zonas = Get-DnsServerZone | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneName -ne "TrustAnchors" }

    foreach ($z in $zonas) {

        $record = Get-DnsServerResourceRecord -ZoneName $z.ZoneName -RRType A | Where-Object { $_.HostName -eq "@" } | Select-Object -First 1

        $ip = if ($record) { $record.RecordData.IPv4Address } else { "Sin IP" }

        Write-Host "$($z.ZoneName) -> $ip"

    }

    Read-Host "Enter para continuar..."

}



# ---------------------------------------------------

# 4. FUNCIONES UNIFICADAS Y MENUS

# ---------------------------------------------------



function Verificar-Estado-Servicio {

    Clear-Host

    Log-Aviso "--- ESTADO DE LOS SERVICIOS ---"

    $servicios = @("DhcpServer", "DNS")

    foreach ($s in $servicios) {

        $status = Get-Service -Name $s -ErrorAction SilentlyContinue

        Write-Host "$s : " -NoNewline

        if ($status -and $status.Status -eq "Running") { Write-Host "[CORRIENDO]" -ForegroundColor Green }

        else { Write-Host "[DETENIDO/NO INSTALADO]" -ForegroundColor Red }

    }

    Read-Host "Enter para continuar..."

}



function SubMenu-DHCP {

    while ($true) {

        Clear-Host

        Write-Host "--- SUBMENU DHCP ---" -ForegroundColor Yellow

        Write-Host "1. Instalar DHCP`n2. Configurar Scope`n3. Ver clientes`n4. Desinstalar`n5. Volver"

        $op = Read-Host "Opcion"

        switch ($op) {

            "1" { Instalar-Rol-DHCP }

            "2" { Configurar-Todo-Scope }

            "3" { Monitorear-Clientes }

            "4" { Uninstall-WindowsFeature DHCP; Log-Exito "Desinstalado." }

            "5" { return }

        }

    }

}



function SubMenu-DNS {
    while ($true) {
        Clear-Host
        Write-Host "--- SUBMENU DNS ---" -ForegroundColor Green
        Write-Host "1. Instalar DNS`n2. Agregar Dominio`n3. Listar Dominios`n4. Eliminar Dominio`n5. Desinstalar`n6. Volver"
        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { Instalar-DNS }
            "2" { Agregar-Dominio-DNS }
            "3" { Listar-Dominios-DNS }
            "4" { Eliminar-Dominio-DNS }
            "5" { Uninstall-WindowsFeature DNS -Remove; Log-Exito "Desinstalado."; Read-Host "Enter..." }
            "6" { return }
        }
    }
}


Verificar-Admin

while ($true) {

    Clear-Host

    Write-Host "--- GESTOR UNIFICADO (WINDOWS SERVER) ---" -ForegroundColor Cyan

    Write-Host "1. DHCP`n2. DNS`n3. Estado`n4. Salir"

    $op = Read-Host "Opcion"

    switch ($op) {

        "1" { SubMenu-DHCP }

        "2" { SubMenu-DNS }

        "3" { Verificar-Estado-Servicio }

        "4" { exit }

    }

}
