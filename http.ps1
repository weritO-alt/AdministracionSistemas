function Instalar-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "  Instalando Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(
            'https://community.chocolatey.org/install.ps1'))
        refreshenv
        Write-Host "  [OK] Chocolatey instalado."
    } else {
        Write-Host "  [OK] Chocolatey ya instalado."
    }
}
function Solicitar-Puerto {
    $reservedPorts = @(1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,
        77,79,110,111,113,115,117,118,119,123,135,137,139,143,161,177,179,
        389,427,445,465,512,513,514,515,526,530,531,532,540,548,554,556,
        563,587,601,636,989,990,993,995,1723,2049,3306,3389,5432)
    $serviciosReservados = @{22="SSH";53="DNS";3306="MySQL";3389="RDP";5432="PostgreSQL";25="SMTP";445="SMB"}
    while ($true) {
        $input = Read-Host "  Ingrese el puerto (ej. 80, 8080, 8888)"
        if ($input -notmatch '^\d+$') { Write-Warning "  Error: Ingresa un numero valido."; continue }
        $puerto = [int]$input
        if ($puerto -le 0 -or $puerto -gt 65535) {
            Write-Warning "  Error: El puerto debe estar entre 1 y 65535."; continue
        }
        if ($reservedPorts -contains $puerto) {
            $desc = if ($serviciosReservados.ContainsKey($puerto)) { $serviciosReservados[$puerto] } else { "Sistema Critico" }
            Write-Warning "  Error: Puerto $puerto reservado para $desc. Elige otro."; continue
        }
        $portInUse = Test-NetConnection -ComputerName localhost -Port $puerto `
            -InformationLevel Quiet -WarningAction SilentlyContinue 2>$null
        if ($portInUse) { Write-Warning "  Error: El puerto $puerto ya esta en uso."; continue }
        return $puerto
    }
}
function Seleccionar-VersionChoco {
    param([string]$Paquete)
    Write-Host "  Consultando versiones de '$Paquete' en Chocolatey..."
    $rawVersions = @()
    try {
        $rawVersions = choco list $Paquete --all-versions --exact --limit-output 2>$null |
            ForEach-Object { ($_ -split '\|')[1] } |
            Where-Object { $_ -match '^\d' } |
            Sort-Object { [version]($_ -replace '[^\d\.]', '') } |
            Select-Object -Last 5
    } catch {}
    if ($rawVersions.Count -eq 0) {
        Write-Warning "  No se encontraron versiones. Usando 'latest'."
        return "latest"
    }
    Write-Host ""; Write-Host "  Versiones disponibles para $Paquete :"
    $i = 1
    foreach ($ver in $rawVersions) {
        $etiqueta = if ($i -eq $rawVersions.Count) { "[Latest / Mas Reciente]" } else { "[Version Estable]" }
        Write-Host "    $i) $ver  --> $etiqueta"
        $i++
    }
    Write-Host ""
    while ($true) {
        $sel = Read-Host "  Selecciona el numero de version (1-$($rawVersions.Count))"
        if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $rawVersions.Count) {
            return $rawVersions[[int]$sel - 1]
        }
        Write-Warning "  Seleccion invalida."
    }
}
function Crear-Index {
    param([string]$Ruta, [string]$Servicio, [string]$Version, [int]$Puerto)
    $osInfo = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    $html = @"
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>$Servicio</title></head>
<body>
  <h1>Servidor: $Servicio</h1>
  <p>Version: $Version</p>
  <p>Puerto: $Puerto</p>
  <p>Sistema: $osInfo</p>
</body>
</html>
"@
    Set-Content -Path "$Ruta\index.html" -Value $html -Encoding UTF8
}
function Configurar-Firewall-Windows {
    param([int]$Puerto)
    Write-Host "  Configurando Windows Firewall para puerto $Puerto..."
    $ruleName = "HTTP-Custom-$Puerto"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound `
            -Protocol TCP -LocalPort $Puerto -Action Allow -Profile Any | Out-Null
        Write-Host "  [+] Regla firewall creada: puerto $Puerto abierto."
    }
    foreach ($p in @(80, 443, 8080, 8888)) {
        if ($p -ne $Puerto) {
            $rule = Get-NetFirewallRule -DisplayName "HTTP-Custom-$p" -ErrorAction SilentlyContinue
            if ($rule) {
                Remove-NetFirewallRule -DisplayName "HTTP-Custom-$p" | Out-Null
                Write-Host "  [-] Regla para puerto $p eliminada (no en uso)."
            }
        }
    }
}
function Liberar-Entorno-Windows {
    Write-Host "  Limpiando entorno Windows..."
    Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
    $apache = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
    if ($apache) { Stop-Service -Name $apache.Name -Force -ErrorAction SilentlyContinue }
    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "  Entorno Windows liberado."
}
function Aplicar-Hardening-IIS {
    param([string]$WebRoot)
    Write-Host "  Aplicando Hardening a IIS..."
    Remove-WebConfigurationProperty -PSPath "IIS:\" `
        -Filter "system.webServer/httpProtocol/customHeaders" `
        -Name "." -AtElement @{name='X-Powered-By'} -ErrorAction SilentlyContinue
    Set-WebConfigurationProperty -PSPath "IIS:\" `
        -Filter "system.webServer/security/requestFiltering" `
        -Name "removeServerHeader" -Value $true -ErrorAction SilentlyContinue
    $webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering removeServerHeader="true">
        <verbs>
          <add verb="TRACE"   allowed="false" />
          <add verb="TRACK"   allowed="false" />
          <add verb="DELETE"  allowed="false" />
          <add verb="PUT"     allowed="false" />
          <add verb="OPTIONS" allowed="false" />
        </verbs>
      </requestFiltering>
    </security>
    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
        <add name="X-Frame-Options"        value="SAMEORIGIN" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-XSS-Protection"       value="1; mode=block" />
        <add name="Referrer-Policy"        value="no-referrer-when-downgrade" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
"@
    Set-Content -Path "$WebRoot\web.config" -Value $webConfig -Encoding UTF8
    Write-Host "  [OK] Security Headers configurados en IIS."
}
function Aplicar-Hardening-Apache-Win {
    param([string]$ApachePath)
    $httpdConf = "$ApachePath\conf\httpd.conf"
    Write-Host "  Aplicando Hardening a Apache Windows..."
    (Get-Content $httpdConf) -replace 'ServerTokens Full','ServerTokens Prod' | Set-Content $httpdConf
    (Get-Content $httpdConf) -replace 'ServerSignature On','ServerSignature Off' | Set-Content $httpdConf
    $secHeaders = @"

# --- Security Headers ---
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "no-referrer-when-downgrade"
    Header always unset X-Powered-By
</IfModule>
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
"@
    Add-Content -Path $httpdConf -Value $secHeaders
    Write-Host "  [OK] Security Headers configurados en Apache Windows."
}
function Aplicar-Hardening-Nginx-Win {
    param([string]$NginxConf, [int]$Puerto)
    Write-Host "  Aplicando Hardening a Nginx Windows..."
    $nginxConfContent = @"
worker_processes  1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;
    server_tokens off;
    server {
        listen       $Puerto;
        server_name  localhost;
        root         html;
        index        index.html;
        add_header X-Frame-Options        "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection       "1; mode=block" always;
        add_header Referrer-Policy        "no-referrer-when-downgrade" always;
        if (`$request_method !~ ^(GET|POST|HEAD)`$) { return 405; }
        location / { try_files `$uri `$uri/ =404; }
        error_page 500 502 503 504 /50x.html;
        location = /50x.html { root html; }
    }
}
"@
    Set-Content -Path $NginxConf -Value $nginxConfContent -Encoding UTF8
    Write-Host "  [OK] Security Headers configurados en Nginx Windows."
}
function Instalar-IIS {
    param([int]$Puerto)
    Write-Host ""; Write-Host "  Instalando IIS en puerto $Puerto..."
    $features = @("IIS-WebServerRole","IIS-WebServer","IIS-CommonHttpFeatures",
        "IIS-StaticContent","IIS-DefaultDocument","IIS-HttpErrors",
        "IIS-Security","IIS-RequestFiltering","IIS-HttpLoggingLibraries","IIS-ManagementConsole")
    foreach ($feature in $features) {
        Enable-WindowsOptionalFeature -Online -FeatureName $feature `
            -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host "  [OK] Caracteristicas de IIS habilitadas."
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $iisVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if (-not $iisVersion) { $iisVersion = "Instalado" }
    Remove-WebBinding -Name "Default Web Site" -ErrorAction SilentlyContinue
    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port $Puerto -IPAddress "*" | Out-Null
    Write-Host "  [OK] Binding configurado en puerto $Puerto."
    $webRoot = "C:\inetpub\wwwroot"
    Aplicar-Hardening-IIS -WebRoot $webRoot
    Crear-Index -Ruta $webRoot -Servicio "IIS" -Version $iisVersion -Puerto $Puerto
    $acl = Get-Acl $webRoot
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","ReadAndExecute","Allow")
    $acl.SetAccessRule($rule); Set-Acl $webRoot $acl
    Write-Host "  [OK] Permisos NTFS configurados para IIS_IUSRS."
    Start-Service W3SVC -ErrorAction SilentlyContinue
    iisreset /restart /noforce 2>$null | Out-Null
    Configurar-Firewall-Windows -Puerto $Puerto
    Write-Host ""; Write-Host "  [OK] IIS instalado y asegurado en puerto $Puerto."
    Write-Host "       Verificar: curl -I http://localhost:$Puerto"
}
function Instalar-Apache-Windows {
    param([string]$Version, [int]$Puerto)
    Instalar-Chocolatey
    Write-Host ""; Write-Host "  Instalando Apache Win64 ($Version) en puerto $Puerto..."
    if ($Version -eq "latest") { choco install apache-httpd -y --no-progress 2>$null }
    else { choco install apache-httpd --version $Version -y --no-progress --allow-downgrade 2>$null }
    $apachePath = "C:\Apache24"
    if (-not (Test-Path $apachePath)) {
        $apachePath = (Get-ChildItem "C:\Program Files\" -Filter "Apache*" `
            -Directory -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    }
    if (-not $apachePath -or -not (Test-Path $apachePath)) {
        Write-Warning "  Apache no encontrado. Verifica la instalacion."; return
    }
    $httpdConf = "$apachePath\conf\httpd.conf"
    (Get-Content $httpdConf) -replace 'Listen 80',"Listen $Puerto" | Set-Content $httpdConf
    (Get-Content $httpdConf) -replace 'Listen 443',"#Listen 443"   | Set-Content $httpdConf
    Aplicar-Hardening-Apache-Win -ApachePath $apachePath
    Crear-Index -Ruta "$apachePath\htdocs" -Servicio "Apache Win64" -Version $Version -Puerto $Puerto
    & "$apachePath\bin\httpd.exe" -k install 2>$null
    & "$apachePath\bin\httpd.exe" -k start   2>$null
    Configurar-Firewall-Windows -Puerto $Puerto
    Write-Host ""; Write-Host "  [OK] Apache Win64 instalado y asegurado en puerto $Puerto."
    Write-Host "       Verificar: curl -I http://localhost:$Puerto"
}
function Instalar-Nginx-Windows {
    param([string]$Version, [int]$Puerto)
    Instalar-Chocolatey
    Write-Host ""; Write-Host "  Instalando Nginx Windows ($Version) en puerto $Puerto..."
    if ($Version -eq "latest") { choco install nginx -y --no-progress 2>$null }
    else { choco install nginx --version $Version -y --no-progress --allow-downgrade 2>$null }
    $nginxPath = "C:\nginx"
    if (-not (Test-Path $nginxPath)) {
        $nginxPath = (Get-ChildItem "C:\ProgramData\chocolatey\lib\" `
            -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
            Select-Object -First 1).FullName
    }
    if (-not $nginxPath -or -not (Test-Path $nginxPath)) {
        Write-Warning "  Nginx no encontrado. Verifica la instalacion."; return
    }
    Aplicar-Hardening-Nginx-Win -NginxConf "$nginxPath\conf\nginx.conf" -Puerto $Puerto
    Crear-Index -Ruta "$nginxPath\html" -Servicio "Nginx Windows" -Version $Version -Puerto $Puerto
    $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source
    if ($nssmPath) { nssm install Nginx "$nginxPath\nginx.exe" 2>$null; nssm start Nginx 2>$null }
    else { Start-Process -FilePath "$nginxPath\nginx.exe" -WorkingDirectory $nginxPath -WindowStyle Hidden }
    Configurar-Firewall-Windows -Puerto $Puerto
    Write-Host ""; Write-Host "  [OK] Nginx Windows instalado y asegurado en puerto $Puerto."
    Write-Host "       Verificar: curl -I http://localhost:$Puerto"
}
function Verificar-Servicio-Windows {
    param([string]$Servicio, [int]$Puerto)
    Write-Host ""; Write-Host "  +------ Verificacion: $Servicio en puerto $Puerto ------+"
    $portCheck = Test-NetConnection -ComputerName localhost -Port $Puerto `
        -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($portCheck) { Write-Host "  [OK] Puerto $Puerto : ESCUCHANDO" }
    else             { Write-Host "  [!!] Puerto $Puerto : NO detectado" }
    Write-Host "  [>>] Encabezados HTTP:"
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$Puerto" `
            -Method Head -UseBasicParsing -ErrorAction SilentlyContinue
        $response.Headers.GetEnumerator() |
            Where-Object { $_.Key -match "Server|X-Frame|X-Content|X-XSS" } |
            ForEach-Object { Write-Host "       $($_.Key): $($_.Value)" }
    } catch { Write-Host "       (Servicio aun iniciando o no accesible)" }
    Write-Host "  +---------------------------------------------------+"
}
function Mostrar-Banner {
    Clear-Host
    $osCaption = (Get-WmiObject Win32_OperatingSystem).Caption
    $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host "  |     SISTEMA DE APROVISIONAMIENTO WEB - WINDOWS      |" -ForegroundColor Cyan
    Write-Host "  |          Practica 6 | PowerShell Automatizado        |" -ForegroundColor Cyan
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host ("  |  Sistema : {0,-42}|" -f $osCaption) -ForegroundColor Gray
    Write-Host ("  |  Fecha   : {0,-42}|" -f $fecha) -ForegroundColor Gray
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host ""
}
function Mostrar-Menu {
    Write-Host "  +-----------------------------------------+"
    Write-Host "  |        SELECCIONA UNA OPCION             |"
    Write-Host "  +-----------------------------------------+"
    Write-Host "  |  1) Instalar IIS (Obligatorio)           |"
    Write-Host "  |  2) Instalar Apache Win64                |"
    Write-Host "  |  3) Instalar Nginx Windows               |"
    Write-Host "  |  4) Verificar servicio activo            |"
    Write-Host "  |  5) Desinstalar servidor especifico      |"
    Write-Host "  |  6) Cambiar version de servidor          |"
    Write-Host "  |  7) Limpiar entorno                      |"
    Write-Host "  |  0) Salir                                |"
    Write-Host "  +-----------------------------------------+"
    Write-Host ""
}
function Leer-Opcion {
    while ($true) {
        $opcion = Read-Host "  Opcion"
        if ($opcion -match '^[0-7]$') { return [int]$opcion }
        Write-Warning "  Opcion invalida. Ingresa un numero del 0 al 7."
    }
}
function Desinstalar-Servidor-Windows {
    Write-Host ""; Write-Host "  ============================================"
    Write-Host "    Desinstalar servidor especifico"
    Write-Host "  ============================================"
    Write-Host "  1) IIS    2) Apache Win64    3) Nginx Windows"; Write-Host ""
    $svcOp = Read-Host "  Selecciona el servidor (1-3)"
    switch ($svcOp) {
        "1" {
            $nombre = "IIS"
            $instalado = (Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -ErrorAction SilentlyContinue).State -eq "Enabled"
            if (-not $instalado) { Write-Host "  IIS no esta instalado actualmente."; return }
            $conf = Read-Host "  Confirmar desinstalacion de IIS? [s/N]"
            if ($conf -notmatch '^[sS]$') { Write-Host "  Cancelado."; return }
            Write-Host "  Deteniendo IIS..."
            Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
            Write-Host "  Desinstalando IIS..."
            $features = @("IIS-WebServerRole","IIS-WebServer","IIS-CommonHttpFeatures",
                "IIS-StaticContent","IIS-DefaultDocument","IIS-HttpErrors",
                "IIS-Security","IIS-RequestFiltering","IIS-ManagementConsole")
            foreach ($f in $features) {
                Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Host "  [OK] IIS desinstalado correctamente."
        }
        "2" {
            $nombre = "Apache Win64"
            $apacheSvc = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
            if (-not $apacheSvc) { Write-Host "  Apache Win64 no esta instalado actualmente."; return }
            $conf = Read-Host "  Confirmar desinstalacion de Apache Win64? [s/N]"
            if ($conf -notmatch '^[sS]$') { Write-Host "  Cancelado."; return }
            Stop-Service -Name $apacheSvc.Name -Force -ErrorAction SilentlyContinue
            choco uninstall apache-httpd -y --no-progress 2>$null
            Remove-Item "C:\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Apache Win64 desinstalado correctamente."
        }
        "3" {
            $nombre = "Nginx Windows"
            $nginxProc = Get-Process nginx -ErrorAction SilentlyContinue
            if (-not $nginxProc) { Write-Host "  Nginx no esta instalado o ejecutandose."; return }
            $conf = Read-Host "  Confirmar desinstalacion de Nginx Windows? [s/N]"
            if ($conf -notmatch '^[sS]$') { Write-Host "  Cancelado."; return }
            $nginxProc | Stop-Process -Force
            $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source
            if ($nssmPath) { nssm remove Nginx confirm 2>$null }
            choco uninstall nginx -y --no-progress 2>$null
            Write-Host "  [OK] Nginx desinstalado correctamente."
        }
        default { Write-Warning "  Opcion invalida."; return }
    }
}
function Cambiar-Version-Windows {
    Write-Host ""; Write-Host "  ============================================"
    Write-Host "    Cambiar version de servidor"
    Write-Host "  ============================================"
    Write-Host "  1) Apache Win64    2) Nginx Windows"; Write-Host ""
    Write-Host "  (IIS no permite seleccion de version via Chocolatey)"; Write-Host ""
    $svcOp = Read-Host "  Selecciona el servidor (1-2)"
    $servicio = ""; $nombre = ""; $paquete = ""
    switch ($svcOp) {
        "1" { $servicio = "Apache"; $nombre = "Apache Win64";   $paquete = "apache-httpd" }
        "2" { $servicio = "Nginx";  $nombre = "Nginx Windows";  $paquete = "nginx" }
        default { Write-Warning "  Opcion invalida."; return }
    }
    $versionActual = choco list $paquete --local-only --exact --limit-output 2>$null |
        ForEach-Object { ($_ -split '\|')[1] } | Select-Object -First 1
    if (-not $versionActual) {
        Write-Host "  $nombre no está instalado. Usa la opcion 'Instalar' primero."
        return
    }
    Write-Host "  Version actual instalada: $versionActual"; Write-Host ""
    $nuevaVersion = Seleccionar-VersionChoco -Paquete $paquete
    if ($nuevaVersion -eq $versionActual) {
        Write-Host "  La version seleccionada ($nuevaVersion) ya esta instalada."
        return
    }
    Write-Host "  Nueva version seleccionada: $nuevaVersion"; Write-Host ""
    $puerto = Solicitar-Puerto
    Write-Host "  Puerto: $puerto"; Write-Host ""
    $conf = Read-Host "  Confirmar cambio de $versionActual a $nuevaVersion en puerto $puerto? [s/N]"
    if ($conf -notmatch '^[sS]$') { Write-Host "  Cancelado."; return }
    Write-Host "  Desinstalando version anterior ($versionActual)..."
    if ($servicio -eq "Apache") {
        $apacheSvc = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
        if ($apacheSvc) { Stop-Service -Name $apacheSvc.Name -Force -ErrorAction SilentlyContinue }
        choco uninstall apache-httpd -y --no-progress 2>$null
        Remove-Item "C:\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force
        $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source
        if ($nssmPath) { nssm remove Nginx confirm 2>$null }
        choco uninstall nginx -y --no-progress 2>$null
    }
    Write-Host "  Instalando nueva version ($nuevaVersion)..."
    switch ($servicio) {
        "Apache" { Instalar-Apache-Windows -Version $nuevaVersion -Puerto $puerto }
        "Nginx"  { Instalar-Nginx-Windows  -Version $nuevaVersion -Puerto $puerto }
    }
}
function Flujo-Instalacion {
    param([string]$Servicio, [string]$Nombre, [string]$PaqueteChoco = "")
    Write-Host ""; Write-Host "  ============================================"
    Write-Host "    Instalacion de $Nombre"
    Write-Host "  ============================================"
    $esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $esAdmin) { Write-Error "  ERROR: Requiere permisos de Administrador."; return }
    $version = ""
    if ($Servicio -eq "IIS") {
        $version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
        if (-not $version) { $version = "Ultima disponible" }
        Write-Host "  Version a instalar: $version"
    } else {
        $version = Seleccionar-VersionChoco -Paquete $PaqueteChoco
        Write-Host "  Version seleccionada: $version"
    }
    Write-Host ""
    $puerto = Solicitar-Puerto
    Write-Host "  Puerto seleccionado: $puerto"; Write-Host ""
    $conf = Read-Host "  Confirmar instalacion de $Nombre en puerto $puerto? [s/N]"
    if ($conf -notmatch '^[sS]$') { Write-Host "  Instalacion cancelada."; return }
    switch ($Servicio) {
        "IIS"    { Instalar-IIS -Puerto $puerto }
        "Apache" { Instalar-Apache-Windows -Version $version -Puerto $puerto }
        "Nginx"  { Instalar-Nginx-Windows  -Version $version -Puerto $puerto }
    }
}
function Flujo-Verificacion {
    Write-Host ""; Write-Host "  ============================================"
    Write-Host "    Verificacion de servicio"
    Write-Host "  ============================================"
    Write-Host "  1) IIS    2) Apache    3) Nginx"; Write-Host ""
    $svcOpcion = Read-Host "  Selecciona el servicio (1-3)"
    $servicio = switch ($svcOpcion) {
        "1" { "IIS" }  "2" { "Apache" }  "3" { "Nginx" }
        default { Write-Warning "  Opcion invalida."; return }
    }
    $puertoStr = Read-Host "  Ingresa el puerto del servicio"
    if ($puertoStr -notmatch '^\d+$') { Write-Warning "  Puerto invalido."; return }
    Verificar-Servicio-Windows -Servicio $servicio -Puerto ([int]$puertoStr)
}
function Main {
    $esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $esAdmin) {
        Write-Host ""; Write-Host "  ERROR: Ejecuta PowerShell como Administrador." -ForegroundColor Red
        Write-Host "  Clic derecho en PowerShell > Ejecutar como administrador" -ForegroundColor Yellow
        Write-Host ""; exit 1
    }
    while ($true) {
        Mostrar-Banner
        Mostrar-Menu
        $opcion = Leer-Opcion
        switch ($opcion) {
            1 { Flujo-Instalacion -Servicio "IIS"    -Nombre "IIS" }
            2 { Flujo-Instalacion -Servicio "Apache" -Nombre "Apache Win64"  -PaqueteChoco "apache-httpd" }
            3 { Flujo-Instalacion -Servicio "Nginx"  -Nombre "Nginx Windows" -PaqueteChoco "nginx" }
            4 { Flujo-Verificacion }
            5 { Desinstalar-Servidor-Windows }
            6 { Cambiar-Version-Windows }
            7 {
                $conf = Read-Host "  Seguro que deseas limpiar el entorno? [s/N]"
                if ($conf -match '^[sS]$') { Liberar-Entorno-Windows }
            }
            0 {
                Write-Host ""; Write-Host "  Saliendo. Hasta luego!" -ForegroundColor Green
                Write-Host ""; exit 0
            }
        }
        Write-Host ""
        Read-Host "  Presiona ENTER para volver al menu"
    }
}
Main
