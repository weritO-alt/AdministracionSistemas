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

    if ((Get-WindowsFeature DHCP).Installed) {
        Log-Exito "DHCP ya instalado."
    } else {
        $resultado = Install-WindowsFeature DHCP -IncludeManagementTools

        if ($resultado.Success) {
            Log-Exito "Instalacion del rol completada."
        } else {
            Log-Error "Fallo la instalacion del rol DHCP. Verifica que tengas acceso a archivos de origen o internet."
            Read-Host "Enter para continuar..."
            return
        }
    }

    # --- AUTORIZACION Y CONFIGURACION POST-INSTALACION (solo una vez) ---
    Log-Aviso "Ejecutando configuracion post-instalacion de DHCP..."

    # Paso 1: Crear grupos de seguridad que DHCP necesita
    Log-Aviso "Creando grupos de seguridad DHCP..."
    netsh dhcp add securitygroups | Out-Null

    # Paso 2: Autorizar el servidor en el dominio/red local
    Log-Aviso "Autorizando servidor DHCP..."
    try {
        $ipServidor = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress
        Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $ipServidor -ErrorAction SilentlyContinue
        Log-Exito "Servidor DHCP autorizado correctamente."
    } catch {
        Log-Aviso "Autorizacion omitida (puede que ya este autorizado o no este en dominio)."
    }

    # Paso 3: Notificar al Service Control Manager que DHCP ya esta configurado
    Log-Aviso "Notificando al sistema que DHCP esta listo..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\DHCP" `
            -Name "InstallState" -Value 1 -ErrorAction SilentlyContinue
    } catch {}

    # Paso 4: Iniciar el servicio
    Log-Aviso "Iniciando servicio DHCP..."
    try {
        Start-Service DhcpServer -ErrorAction Stop
        Log-Exito "Servicio DHCP corriendo al 100%."
    } catch {
        Log-Error "No se pudo iniciar el servicio: $_"
    }

    Read-Host "Enter para continuar..."

}



function Configurar-Todo-Scope {

    # Verificar que el servicio DHCP este corriendo antes de configurar
    $servicio = Get-Service -Name DhcpServer -ErrorAction SilentlyContinue
    if (-not $servicio -or $servicio.Status -ne "Running") {
        Log-Error "El servicio DHCP no esta corriendo. Instala y configura DHCP primero (Opcion 1)."
        Read-Host "Enter para continuar..."
        return
    }

    Log-Aviso "--- CONFIGURACION DE RED Y SCOPE (DHCP + DNS) ---"

    Get-NetAdapter | Select-Object Name, Status | Format-Table -AutoSize

    $NombreInterfaz = Read-Host "Nombre del adaptador [Default: Ethernet 2]"

    if ($NombreInterfaz -eq "") { $NombreInterfaz = "Ethernet 2" }



    $RangoInicio = Pedir-IP-Segura "1. IP Inicio Rango"

    

    while ($true) {

        $RangoFin = Pedir-IP-Segura "2. IP Fin Rango"

        if ([Version]$RangoFin -gt [Version]$RangoInicio) { break }

        else { Log-Error "La IP Final debe ser mayor a $RangoInicio." }

    }

    $IPServidor = Pedir-IP-Segura "3. IP Estatica del Servidor (fuera del rango DHCP recomendado)"

    $Prefijo = Read-Host "4. Prefijo (24, 16, 8) [Default: 24]"

    if ($Prefijo -eq "") { $Prefijo = 24 }

    $Mascara = Obtener-Mascara-Desde-Prefijo ([int]$Prefijo)

    

    $Gateway = Pedir-IP-Segura "5. Gateway (Enter para omitir)" "si"

    $DnsServer = Pedir-IP-Segura "6. DNS (Recomendado: La IP de este servidor)"

    

    $NombreScope = Read-Host "7. Nombre del Scope"

    $TiempoLease = Pedir-Entero "8. Tiempo Lease (segundos)"



    Log-Aviso "Configurando IP Estatica en la interfaz..."

    try {

        Remove-NetIPAddress -InterfaceAlias $NombreInterfaz -Confirm:$false -ErrorAction SilentlyContinue

        if ($Gateway) {

            New-NetIPAddress -InterfaceAlias $NombreInterfaz -IPAddress $IPServidor -PrefixLength $Prefijo -DefaultGateway $Gateway -ErrorAction SilentlyContinue

        } else {

            New-NetIPAddress -InterfaceAlias $NombreInterfaz -IPAddress $IPServidor -PrefixLength $Prefijo -ErrorAction SilentlyContinue

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

        
        # Excluir la IP del servidor del rango para evitar conflictos
        try {
            Add-DhcpServerv4ExclusionRange -ScopeId $netID -StartRange $IPServidor -EndRange $IPServidor -ErrorAction SilentlyContinue
            Log-Aviso "IP del servidor ($IPServidor) excluida del rango DHCP."
        } catch {}

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

    # Listar scopes disponibles primero
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



# ---------------------------------------------------

# 3. MODULO DNS

# ---------------------------------------------------



function Instalar-DNS {
    Clear-Host
    Log-Aviso "--- INSTALACION DE DNS ---"
    Log-Aviso "Instalando el rol de DNS y sus herramientas..."
    
    $resultado = Install-WindowsFeature -Name DNS -IncludeManagementTools

    if ($resultado.Success) {
        Import-Module DnsServer -ErrorAction SilentlyContinue
        Start-Service DNS -ErrorAction SilentlyContinue
        Log-Exito "DNS Instalado y corriendo al 100%."
    } else {
        Log-Error "Fallo la instalacion de DNS. Verifica acceso a archivos de origen o internet."
    }
    
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

            "4" { 
                $confirm = Read-Host "Seguro que quieres desinstalar DHCP? (s/n)"
                if ($confirm -eq "s") { Uninstall-WindowsFeature DHCP; Log-Exito "Desinstalado." }
            }

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
            "5" { 
                $confirm = Read-Host "Seguro que quieres desinstalar DNS? (s/n)"
                if ($confirm -eq "s") { Uninstall-WindowsFeature DNS -Remove; Log-Exito "Desinstalado."; Read-Host "Enter..." }
            }
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
