# Archivo: funciones_ssl.ps1

$global:resumenInstalaciones = @()

function Escribir-Resumen {
    param([string]$mensaje)
    $global:resumenInstalaciones += $mensaje
}

function Mostrar-Resumen {
    Write-Host "`n========== RESUMEN DE INSTALACIONES ==========" -ForegroundColor Magenta
    if ($global:resumenInstalaciones.Count -eq 0) {
        Write-Host "No se registraron instalaciones en esta sesion." -ForegroundColor Yellow
    } else {
        $global:resumenInstalaciones | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
    }
    Write-Host "==============================================" -ForegroundColor Magenta
}

function Liberar-Puertos-Web {
    Write-Host "Iniciando limpieza profunda del entorno (Liberando puertos 80 y 443)..." -ForegroundColor Yellow
    
    taskkill /F /IM httpd.exe /T 2>$null
    taskkill /F /IM nginx.exe /T 2>$null

    Stop-Service -Name "W3SVC" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "WAS" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "Apache-Practica7" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "apache" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "Apache2.4" -Force -ErrorAction SilentlyContinue

    sc.exe delete "Apache-Practica7" | Out-Null
    sc.exe delete "apache" | Out-Null
    sc.exe delete "Apache2.4" | Out-Null

    Remove-Item -Path "C:\tools\apache24" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:APPDATA\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\tools\nginx" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\nginx" -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "C:\" -Filter "nginx-*" -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (Get-Website -Name "SitioIIS_Practica7" -ErrorAction SilentlyContinue) { Remove-Website -Name "SitioIIS_Practica7" }
    if (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue) { Remove-Website -Name "Default Web Site" }

    Write-Host "Entorno 100% liberado y limpio." -ForegroundColor Green
}

function Instalar-Apache {
    Write-Host "--- INSTALANDO APACHE ---" -ForegroundColor Cyan
    Liberar-Puertos-Web
    
    Write-Host "1) Descargar de la Web (Via Chocolatey)"
    Write-Host "2) Descargar del FTP (Privado)"
    $origen = Read-Host "Selecciona el origen"

    $apacheDir = "C:\Apache24"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $chocoExe = "C:\ProgramData\chocolatey\bin\choco.exe"

    if ($origen -eq "1") {
        Write-Host "Preparando instalacion via Chocolatey..."
        if (-not (Test-Path $chocoExe)) {
            Write-Host "Instalando gestor de paquetes Chocolatey..."
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        Write-Host "Extrayendo Apache desde cache local/repositorio (Silencioso)..."
        & $chocoExe install apache-httpd -y --force --params '"/NoService"' --limit-output
        
        $tempDir = ""
        if (Test-Path "C:\tools\apache24") { $tempDir = "C:\tools\apache24" }
        elseif (Test-Path "$env:APPDATA\Apache24") { $tempDir = "$env:APPDATA\Apache24" }
        elseif (Test-Path "C:\Apache24") { $tempDir = "C:\Apache24" }

        if ($tempDir -eq "") {
            Write-Host "Error: Fallo la instalacion por Choco." -ForegroundColor Red
            return
        }

        if ($tempDir -ne "C:\Apache24") {
            Write-Host "Forzando directorio base a C:\Apache24..."
            if (Test-Path "C:\Apache24") { Remove-Item -Path "C:\Apache24" -Recurse -Force }
            Move-Item -Path $tempDir -Destination "C:\Apache24" -Force
        }
    } else {
        $rutaZip = Navegar-Descargar-FTP -Servicio "Apache"
        if (-not $rutaZip) { return }
        Write-Host "Extrayendo Apache en C:\ ..."
        Expand-Archive -Path $rutaZip -DestinationPath "C:\" -Force
    }

    $resSSL = Read-Host "Desea activar SSL en este servicio? [S/N]"
    $isSSL = ($resSSL -eq "S" -or $resSSL -eq "s")

    $confPath = "$apacheDir\conf\httpd.conf"
    
    $confArray = Get-Content $confPath | Where-Object { $_ -notmatch '^\s*Listen ' -and $_ -notmatch '^\s*ServerName ' }
    $conf = $confArray -join "`r`n"
    
    $conf = "Listen 80`r`nServerName localhost:80`r`n" + $conf
    $conf = $conf -replace 'Define SRVROOT ".*"', 'Define SRVROOT "C:/Apache24"'
    $conf = $conf -replace '(?m)^\s*Include conf/extra/httpd-ahssl\.conf.*$', '#Include conf/extra/httpd-ahssl.conf'
    $conf = $conf -replace '(?m)^\s*Include conf/extra/httpd-ssl\.conf.*$', '#Include conf/extra/httpd-ssl.conf'

    if ($isSSL) {
        Write-Host "Generando PKI con OpenSSL para www.reprobados.com..."
        
        $env:OPENSSL_CONF = "$apacheDir\conf\openssl.cnf"
        
        Set-Location "$apacheDir\bin"
        .\openssl.exe req -x509 -nodes -newkey rsa:2048 -keyout "$apacheDir\conf\server.key" -out "$apacheDir\conf\server.crt" -days 365 -subj "/CN=www.reprobados.com"
        Set-Location "C:\"

        $conf = $conf -replace '(?m)^#?\s*LoadModule ssl_module.*$', 'LoadModule ssl_module modules/mod_ssl.so'
        $conf = $conf -replace '(?m)^#?\s*LoadModule socache_shmcb_module.*$', 'LoadModule socache_shmcb_module modules/mod_socache_shmcb.so'
        $conf = $conf -replace '(?m)^#?\s*LoadModule rewrite_module.*$', 'LoadModule rewrite_module modules/mod_rewrite.so'
        $conf = $conf -replace '(?m)^#?\s*LoadModule headers_module.*$', 'LoadModule headers_module modules/mod_headers.so'
        
        $conf += "`r`nInclude conf/extra/httpd-ssl.conf"
        $conf += "`r`n<VirtualHost *:80>`r`n    ServerName www.reprobados.com`r`n    RewriteEngine On`r`n    RewriteCond %{HTTPS} off`r`n    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`r`n</VirtualHost>"

        $sslConfContent = @"
Listen 443
SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
SSLProxyCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
SSLHonorCipherOrder on
SSLProtocol all -SSLv3
SSLProxyProtocol all -SSLv3
SSLPassPhraseDialog  builtin
SSLSessionCache "shmcb:c:/Apache24/logs/ssl_scache(512000)"
SSLSessionCacheTimeout  300

<VirtualHost _default_:443>
    DocumentRoot "c:/Apache24/htdocs"
    ServerName www.reprobados.com:443
    ServerAdmin admin@reprobados.com
    ErrorLog "c:/Apache24/logs/error.log"
    TransferLog "c:/Apache24/logs/access.log"

    SSLEngine on
    SSLCertificateFile "c:/Apache24/conf/server.crt"
    SSLCertificateKeyFile "c:/Apache24/conf/server.key"

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
"@
        Set-Content -Path "$apacheDir\conf\extra\httpd-ssl.conf" -Value $sslConfContent -Force
        Escribir-Resumen "[OK] Apache instalado: HSTS en puerto 443 (HTTP redireccionado desde 80)."
    } else {
        $conf = $conf -replace '(?m)^\s*LoadModule ssl_module.*$', '#LoadModule ssl_module modules/mod_ssl.so'
        Escribir-Resumen "[OK] Apache instalado de forma estricta (Puro HTTP) en puerto 80."
    }

    $conf | Set-Content $confPath

    Write-Host "Generando Monitor de Estado en index.html..." -ForegroundColor Yellow
    $versionFull = (& "$apacheDir\bin\httpd.exe" -v | Select-String "Server version")
    $versionClean = ($versionFull -split "/")[1] -replace " .*", ""
    $protocolo = if ($isSSL) { "HTTPS (Seguro)" } else { "HTTP (Inseguro)" }
    $puerto = if ($isSSL) { "443" } else { "80" }
    $bgColor = if ($isSSL) { "#27ae60" } else { "#2c3e50" }

    $htmlContent = @"
<html>
<body style='font-family: Arial; text-align: center; background-color: $bgColor; color: white; padding-top: 50px;'>
    <div style='background: rgba(0,0,0,0.5); display: inline-block; padding: 40px; border-radius: 20px; border: 3px solid white;'>
        <h1 style='margin: 0;'>SERVIDOR WEB: APACHE</h1>
        <hr style='width: 80%; margin: 20px auto;'>
        <p style='font-size: 1.3em;'><b>Version:</b> $versionClean</p>
        <p style='font-size: 1.3em;'><b>Protocolo:</b> $protocolo</p>
        <p style='font-size: 1.3em;'><b>Puerto:</b> $puerto</p>
        <p style='font-size: 1.1em; color: #ecf0f1;'>Configuracion para www.reprobados.com</p>
    </div>
</body>
</html>
"@
    Set-Content -Path "$apacheDir\htdocs\index.html" -Value $htmlContent -Force

    Write-Host "Iniciando proceso de Apache en segundo plano..."
    Start-Process -FilePath "$apacheDir\bin\httpd.exe" -WindowStyle Hidden

    New-NetFirewallRule -DisplayName "Apache HTTP 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow | Out-Null
    if ($isSSL) { New-NetFirewallRule -DisplayName "Apache HTTPS 443" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow | Out-Null }
    
    Write-Host "Instalacion de Apache completada." -ForegroundColor Green
}

function Instalar-Nginx {
    Write-Host "--- INSTALANDO NGINX ---" -ForegroundColor Cyan
    Liberar-Puertos-Web
    
    Write-Host "1) Descargar de la Web (Via Chocolatey)"
    Write-Host "2) Descargar del FTP (Privado)"
    $origen = Read-Host "Selecciona el origen"

    $nginxDir = "C:\nginx"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $chocoExe = "C:\ProgramData\chocolatey\bin\choco.exe"

    $viejoProgreso = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"

    if ($origen -eq "1") {
        Write-Host "Preparando instalacion via Chocolatey..."
        if (-not (Test-Path $chocoExe)) {
            Write-Host "Instalando gestor de paquetes Chocolatey..."
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        Write-Host "Extrayendo Nginx (Modo Ultra Silencioso)..."
        & $chocoExe install nginx -y --force --params '"/port:8080"' *>$null
        
        Stop-Service -Name "nginx" -Force -ErrorAction SilentlyContinue
        sc.exe delete "nginx" | Out-Null
        
        $tempDir = ""
        $posiblesRutas = @("C:\tools", "C:\", $env:APPDATA, $env:ProgramData)
        
        foreach ($ruta in $posiblesRutas) {
            if (Test-Path $ruta) {
                $encontrado = Get-ChildItem -Path $ruta -Filter "nginx-*" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $encontrado) {
                    $encontrado = Get-ChildItem -Path $ruta -Filter "nginx" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                }
                if ($encontrado) {
                    $tempDir = $encontrado.FullName
                    break
                }
            }
        }

        if ($tempDir -eq "") {
            Write-Host "Error: Fallo la instalacion por Choco." -ForegroundColor Red
            $ProgressPreference = $viejoProgreso
            return
        }

        if ($tempDir -ne "C:\nginx") {
            Write-Host "Forzando directorio base a C:\nginx..."
            if (Test-Path "C:\nginx") { Remove-Item -Path "C:\nginx" -Recurse -Force }
            Move-Item -Path $tempDir -Destination "C:\nginx" -Force
        }
    } else {
        $rutaZip = Navegar-Descargar-FTP -Servicio "Nginx"
        
        if (-not $rutaZip) { 
            $ProgressPreference = $viejoProgreso
            return 
        }
        
        Write-Host "Extrayendo Nginx en C:\ ..."
        Expand-Archive -Path $rutaZip -DestinationPath "C:\" -Force
        $busqueda = Get-ChildItem -Path "C:\" -Filter "nginx-*" -Directory | Select-Object -First 1
        
        if ($busqueda.FullName -ne "C:\nginx") {
            if (Test-Path "C:\nginx") { Remove-Item -Path "C:\nginx" -Recurse -Force }
            Move-Item -Path $busqueda.FullName -Destination "C:\nginx" -Force
        }
    }

    $resSSL = Read-Host "Desea activar SSL en este servicio? [S/N]"
    $isSSL = ($resSSL -eq "S" -or $resSSL -eq "s")

    if ($isSSL) {
        $opensslExe = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
        
        if (-not (Test-Path $opensslExe)) {
            Write-Host "Instalando OpenSSL via Chocolatey (Modo Ultra Silencioso)..."
            & $chocoExe install openssl -y *>$null
        } else {
            Write-Host "OpenSSL ya esta instalado. Omitiendo descarga." -ForegroundColor Green
        }

        Write-Host "Generando PKI para www.reprobados.com..."
        
        if (-not (Test-Path "$nginxDir\conf")) { New-Item -ItemType Directory -Path "$nginxDir\conf" -Force | Out-Null }
        
        $env:OPENSSL_CONF = "C:\Program Files\OpenSSL-Win64\bin\openssl.cfg"
        
        & $opensslExe req -x509 -nodes -newkey rsa:2048 -keyout "$nginxDir\conf\server.key" -out "$nginxDir\conf\server.crt" -days 365 -subj "/CN=www.reprobados.com" 2>$null

        $nginxConf = @"
worker_processes  1;
events { worker_connections  1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       80;
        server_name  www.reprobados.com;
        return 301 https://`$host`$request_uri;
    }

    server {
        listen       443 ssl;
        server_name  www.reprobados.com;

        ssl_certificate      server.crt;
        ssl_certificate_key  server.key;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
"@
        Set-Content -Path "$nginxDir\conf\nginx.conf" -Value $nginxConf -Force
        Escribir-Resumen "[OK] Nginx instalado: HSTS en puerto 443 (HTTP redireccionado desde 80)."
    } else {
        $nginxConf = @"
worker_processes  1;
events { worker_connections  1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    server {
        listen       80;
        server_name  localhost;
        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
"@
        Set-Content -Path "$nginxDir\conf\nginx.conf" -Value $nginxConf -Force
        Escribir-Resumen "[OK] Nginx instalado de forma estricta (Puro HTTP) en puerto 80."
    }

    Write-Host "Generando Monitor de Estado en index.html..." -ForegroundColor Yellow
    $version = (& "$nginxDir\nginx.exe" -v 2>&1) -replace '.*nginx/', ''
    $protocolo = if ($isSSL) { "HTTPS (Seguro)" } else { "HTTP (Inseguro)" }
    $puerto = if ($isSSL) { "443" } else { "80" }
    $bgColor = if ($isSSL) { "#115c2a" } else { "#2c3e50" }

    $htmlContent = @"
<html>
<body style='font-family: Arial; text-align: center; background-color: $bgColor; color: white; padding-top: 50px;'>
    <div style='background: rgba(0,0,0,0.5); display: inline-block; padding: 40px; border-radius: 20px; border: 3px solid white;'>
        <h1 style='margin: 0;'>SERVIDOR WEB: NGINX</h1>
        <hr style='width: 80%; margin: 20px auto;'>
        <p style='font-size: 1.3em;'><b>Version:</b> $version</p>
        <p style='font-size: 1.3em;'><b>Protocolo:</b> $protocolo</p>
        <p style='font-size: 1.3em;'><b>Puerto:</b> $puerto</p>
        <p style='font-size: 1.1em; color: #ecf0f1;'>Configuracion para www.reprobados.com</p>
    </div>
</body>
</html>
"@
    if (-not (Test-Path "$nginxDir\html")) { New-Item -ItemType Directory -Path "$nginxDir\html" -Force | Out-Null }
    Set-Content -Path "$nginxDir\html\index.html" -Value $htmlContent -Force

    Write-Host "Iniciando proceso de Nginx en segundo plano..."
    Start-Process -FilePath "$nginxDir\nginx.exe" -WorkingDirectory $nginxDir -WindowStyle Hidden

    New-NetFirewallRule -DisplayName "Nginx HTTP 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow | Out-Null
    if ($isSSL) { New-NetFirewallRule -DisplayName "Nginx HTTPS 443" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow | Out-Null }
    
    $ProgressPreference = $viejoProgreso
    Write-Host "Instalacion de Nginx completada." -ForegroundColor Green
}

function Instalar-IIS-Web {
    Write-Host "--- INSTALANDO IIS WEB ---" -ForegroundColor Cyan
    Liberar-Puertos-Web
    
    Write-Host "Instalando caracteristicas base de IIS..."
    Install-WindowsFeature -name Web-Server -IncludeManagementTools | Out-Null

    Start-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    Start-Service -Name "WAS" -ErrorAction SilentlyContinue
    
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    Write-Host "Limpiando sitios IIS antiguos..."
    Get-Website | ForEach-Object { 
        Stop-Website -Name $_.Name -ErrorAction SilentlyContinue
        Remove-Website -Name $_.Name -ErrorAction SilentlyContinue 
    }

    $resSSL = Read-Host "Desea activar SSL en este servicio? [S/N]"
    $isSSL = ($resSSL -eq "S" -or $resSSL -eq "s")

    $siteName = "SitioIIS_Practica7"
    $sitePath = "C:\inetpub\wwwroot\$siteName"
    
    if (Test-Path $sitePath) { Remove-Item -Path $sitePath -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $sitePath | Out-Null
    
    if ($isSSL) {
        Write-Host "Verificando Modulo URL Rewrite para IIS (Silencioso)..."
        $chocoExe = "C:\ProgramData\chocolatey\bin\choco.exe"
        if (-not (Test-Path $chocoExe)) {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        & $chocoExe install urlrewrite -y --force *>$null
        
        Write-Host "Reiniciando IIS para aplicar modulos..."
        iisreset /restart | Out-Null

        Add-Content -Path "$sitePath\index.html" -Value "<h1>IIS Seguro (HTTPS) - www.reprobados.com</h1>" -Force
        Write-Host "Generando PKI para www.reprobados.com..."
        $cert = New-SelfSignedCertificate -DnsName "www.reprobados.com" -CertStoreLocation "cert:\LocalMachine\My"
        
        New-Website -Name $siteName -Port 80 -PhysicalPath $sitePath -Force | Out-Null
        New-WebBinding -Name $siteName -Protocol "https" -Port 443 -IPAddress "*"
        
        Push-Location IIS:\SslBindings
        Remove-Item -Path "*!443" -Force -ErrorAction SilentlyContinue
        Get-Item "cert:\LocalMachine\My\$($cert.Thumbprint)" | New-Item -Path "*!443" -Force | Out-Null
        Pop-Location
        
        $webConfig = "$sitePath\web.config"
        $configContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="HTTP to HTTPS Redirection" stopProcessing="true">
                    <match url="(.*)" />
                    <conditions><add input="{HTTPS}" pattern="^OFF$" /></conditions>
                    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
                </rule>
            </rules>
        </rewrite>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"@
        Set-Content -Path $webConfig -Value $configContent -Force
        New-NetFirewallRule -DisplayName "IIS HTTPS 443" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "IIS HTTP 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Escribir-Resumen "[OK] IIS Web instalado: HSTS en puerto 443 (HTTP redireccionado desde puerto 80)."
    } else {
        Add-Content -Path "$sitePath\index.html" -Value "<h1>IIS Inseguro (HTTP) - Puerto 80</h1>" -Force
        New-Website -Name $siteName -Port 80 -PhysicalPath $sitePath -Force | Out-Null
        New-NetFirewallRule -DisplayName "IIS HTTP 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Escribir-Resumen "[OK] IIS Web instalado sin SSL en puerto 80."
    }
    
    Start-Website -Name $siteName -ErrorAction SilentlyContinue
    Write-Host "IIS Web configurado." -ForegroundColor Green
}

function Instalar-IIS-FTP {
    Write-Host "--- INSTALANDO IIS FTP ---" -ForegroundColor Cyan
    Install-WindowsFeature Web-FTP-Server -IncludeManagementTools | Out-Null
    
    $ftpUser = Read-Host "Ingresa el nombre del usuario de la Practica 5 que deseas reutilizar"
    
    $ADSI = [ADSI]"WinNT://$env:ComputerName"
    $usuarioExiste = $ADSI.Children | Where-Object { $_.SchemaClassName -eq 'User' -and $_.Name -eq $ftpUser }
    
    if (-not $usuarioExiste) {
        Write-Host "El usuario $ftpUser no existe en el sistema. Debes crearlo primero con el script de la Practica 5." -ForegroundColor Red
        return
    }

    $ftpPath = "C:\FTP\LocalUser\$ftpUser"
    if (-not (Test-Path $ftpPath)) { 
        Write-Host "La ruta de la Practica 5 ($ftpPath) no existe en el disco." -ForegroundColor Red
        return 
    }

    Write-Host "Aplicando permisos NTFS sobre la carpeta del usuario reciclado..."
    icacls $ftpPath /grant "${ftpUser}:(OI)(CI)(F)" /T | Out-Null
    icacls $ftpPath /grant "IUSR:(OI)(CI)(RX)" /T | Out-Null
    icacls $ftpPath /grant "IIS_IUSRS:(OI)(CI)(RX)" /T | Out-Null

    $resSSL = Read-Host "Desea activar SSL en este servicio FTP? [S/N]"
    $isSSL = ($resSSL -eq "S" -or $resSSL -eq "s")

    if ($isSSL) {
        $puerto = 990
    } else {
        $puerto = 21
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (Get-WebSite -Name "FTP_Practica7" -ErrorAction SilentlyContinue) { Remove-WebSite -Name "FTP_Practica7" }

    New-WebFtpSite -Name "FTP_Practica7" -Port $puerto -PhysicalPath $ftpPath -Force | Out-Null
    
    Set-ItemProperty "IIS:\Sites\FTP_Practica7" -Name ftpServer.userIsolation.mode -Value 0
    Remove-WebConfigurationProperty -Filter "/system.ftpServer/security/authorization" -Name "." -Location "FTP_Practica7" -ErrorAction SilentlyContinue

    if ($isSSL) {
        Write-Host "Generando PKI FTP para www.reprobados.com..."
        $cert = New-SelfSignedCertificate -DnsName "www.reprobados.com" -CertStoreLocation "cert:\LocalMachine\My"
        
        Set-ItemProperty "IIS:\Sites\FTP_Practica7" -Name ftpServer.security.ssl.serverCertHash -Value $cert.Thumbprint
        Set-ItemProperty "IIS:\Sites\FTP_Practica7" -Name ftpServer.security.ssl.controlChannelPolicy -Value 1
        Set-ItemProperty "IIS:\Sites\FTP_Practica7" -Name ftpServer.security.ssl.dataChannelPolicy -Value 1
        New-NetFirewallRule -DisplayName "IIS FTPS 990" -Direction Inbound -LocalPort 990 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Escribir-Resumen "[OK] IIS FTP instalado con FTPS (Tunel SSL) en puerto 990. Cert: www.reprobados.com"
    } else {
        Set-ItemProperty "IIS:\Sites\FTP_Practica7" -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
        Set-ItemProperty "IIS:\Sites\FTP_Practica7" -Name ftpServer.security.ssl.dataChannelPolicy -Value 0
        New-NetFirewallRule -DisplayName "IIS FTP 21" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
        Escribir-Resumen "[OK] IIS FTP instalado sin SSL en puerto 21."
    }
    
    Set-ItemProperty "IIS:\Sites\FTP_Practica7" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";users=$ftpUser;permissions="Read,Write"} -PSPath IIS:\ -Location "FTP_Practica7"
    Restart-WebItem "IIS:\Sites\FTP_Practica7"
    
    Write-Host "IIS FTP configurado exitosamente para el usuario $ftpUser en el puerto $puerto." -ForegroundColor Green
}

function Navegar-Descargar-FTP {
    param(
        [string]$Servicio # Recibe "Apache" o "Nginx"
    )

    Write-Host "--- BUSCANDO INSTALADORES DE $Servicio EN FTP ---" -ForegroundColor Cyan
    
    $ftpUser = "repositorio"
    $ftpPassword = "Hola1234."
    
    $urlBase = "ftp://localhost:21/"
    $dirDescargas = "C:\descargas_ftp"

    if (-not (Test-Path $dirDescargas)) { New-Item -ItemType Directory -Force -Path $dirDescargas | Out-Null }

    # FIX: Se corrigio la variable indefinida $repositorio por la cadena literal correcta
    $urlVersiones = "${urlBase}repositorio/${Servicio}/"
    
    Write-Host "Listando versiones disponibles en: /repositorio/$Servicio" -ForegroundColor Cyan
    $archivosRaw = curl.exe -s -l -k -u "${ftpUser}:${ftpPassword}" $urlVersiones
    
    $archivos = $archivosRaw -split "`n" | Where-Object { $_.Trim() -match "\.zip$" }

    if ($archivos.Count -eq 0) { 
        Write-Host "Error: No hay archivos .zip en la ruta $urlVersiones" -ForegroundColor Red
        Write-Host "Verifica que los archivos esten en: C:\FTP\LocalUser\repositorio\repositorio\$Servicio" -ForegroundColor Yellow
        return $null 
    }

    for ($i = 0; $i -lt $archivos.Count; $i++) { 
        Write-Host "$($i+1)) $($archivos[$i].Trim())" 
    }
    
    $selVer = Read-Host "Selecciona el numero de version"
    $archivoElegido = $archivos[[int]$selVer - 1].Trim()

    Write-Host "Descargando instalador y firma SHA256..." -ForegroundColor Cyan
    $rutaInstalador = "$dirDescargas\$archivoElegido"
    $rutaHash = "$dirDescargas\$archivoElegido.sha256"

    curl.exe -s --show-error -k -u "${ftpUser}:${ftpPassword}" "${urlVersiones}${archivoElegido}" -o $rutaInstalador
    curl.exe -s --show-error -k -u "${ftpUser}:${ftpPassword}" "${urlVersiones}${archivoElegido}.sha256" -o $rutaHash

    if ((Test-Path $rutaInstalador) -and (Test-Path $rutaHash)) {
        $hashCalculado = (Get-FileHash -Path $rutaInstalador -Algorithm SHA256).Hash.ToLower()
        $hashOriginalRaw = Get-Content -Path $rutaHash -Raw
        $hashOriginal = ($hashOriginalRaw -split "\s+")[0].ToLower()

        if ($hashCalculado -eq $hashOriginal) {
            Write-Host "Integridad confirmada (SHA256 OK)." -ForegroundColor Green
            return $rutaInstalador
        } else {
            Write-Host "Error: El archivo descargado no coincide con su firma." -ForegroundColor Red
            return $null
        }
    } else {
        Write-Host "Error: Fallo la descarga de los archivos desde el FTP." -ForegroundColor Red
        return $null
    }
}

# =============================================
#   MENU PRINCIPAL - PUNTO DE ENTRADA
# =============================================
function Mostrar-Menu {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Magenta
    Write-Host "   PRACTICA 7 - INFRAESTRUCTURA SSL/TLS      " -ForegroundColor Magenta
    Write-Host "=============================================" -ForegroundColor Magenta
    Write-Host "  1) Instalar Apache"
    Write-Host "  2) Instalar Nginx"
    Write-Host "  3) Instalar IIS Web"
    Write-Host "  4) Instalar IIS FTP"
    Write-Host "  5) Mostrar Resumen de Instalaciones"
    Write-Host "  6) Salir"
    Write-Host "=============================================" -ForegroundColor Magenta

    $op = Read-Host "Selecciona una opcion"
    switch ($op) {
        "1" { Instalar-Apache }
        "2" { Instalar-Nginx }
        "3" { Instalar-IIS-Web }
        "4" { Instalar-IIS-FTP }
        "5" { Mostrar-Resumen }
        "6" { 
            Mostrar-Resumen
            Write-Host "Saliendo..." -ForegroundColor Yellow
            exit 
        }
        default { Write-Host "Opcion no valida. Intenta de nuevo." -ForegroundColor Red }
    }
}

# Bucle principal
do { Mostrar-Menu } while ($true)
