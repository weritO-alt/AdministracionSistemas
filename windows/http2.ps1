# =============================================================
#   PRACTICA 7 - Orquestador de Instalacion con SSL/TLS
#   Sistema: Windows Server 2019
#   Servicios WEB : IIS, Apache, Nginx
#   FTP           : vsftpd en Fedora (FTPS explicito puerto 21)
#
#   Ejecutar como Administrador:
#   powershell -ExecutionPolicy Bypass -File practica7_windows.ps1
# =============================================================

#Requires -RunAsAdministrator

# -------------------------------------------------------------
# VARIABLES GLOBALES
# -------------------------------------------------------------
$FTP_SERVER = "192.168.114.129"   # IP de Fedora
$FTP_USER   = "repositorio"
$FTP_PASS   = "Hola1234."
$FTP_BASE   = "Linux/Windows"     # Ruta en el FTP de Fedora

$BASE_DIR   = "C:\Servicios"
$APACHE_DIR = "$BASE_DIR\Apache"
$NGINX_DIR  = "$BASE_DIR\Nginx"
$SSL_DIR    = "$BASE_DIR\SSL"

$script:RESUMEN_INSTALACIONES = @()
$script:SERVICIOS_VERIFICAR   = @()

# -------------------------------------------------------------
# MENU PRINCIPAL
# -------------------------------------------------------------
function Main {
    while ($true) {
        Write-Host ""
        Write-Host "==========================================================" -ForegroundColor Magenta
        Write-Host "   PRACTICA 7 - ORQUESTADOR DE SERVICIOS (WINDOWS)        " -ForegroundColor Magenta
        Write-Host "==========================================================" -ForegroundColor Magenta
        Write-Host " 1) Instalar IIS Web"
        Write-Host " 2) Instalar Apache"
        Write-Host " 3) Instalar Nginx"
        Write-Host " 4) Ver Resumen de Instalaciones"
        Write-Host " 0) Salir"
        Write-Host "==========================================================" -ForegroundColor Magenta
        $opcion = Read-Host "Selecciona una opcion"

        switch ($opcion) {
            "0" { Mostrar-Resumen; Write-Host "Saliendo..." -ForegroundColor Yellow; return }
            "4" { Mostrar-Resumen; continue }
            { $_ -in "1","2","3" } { }
            default { Write-Host "Opcion invalida." -ForegroundColor Red; continue }
        }

        Write-Host ""
        Write-Host "De donde deseas instalar?"
        Write-Host " 1) WEB (descarga directa desde Internet)"
        Write-Host " 2) FTP (repositorio Fedora: $FTP_SERVER con FTPS)"
        Write-Host " 0) Regresar"
        $origen = Read-Host "Selecciona origen"
        if ($origen -eq "0") { continue }
        $web_ftp = if ($origen -eq "2") { "FTP" } else { "WEB" }

        $ssl = Preguntar-SSL
        if ($ssl -eq "REGRESAR") { continue }

        $archivo = ""
        if ($web_ftp -eq "FTP") {
            $carpeta = switch ($opcion) {
                "1" { "IIS"    }
                "2" { "Apache" }
                "3" { "Nginx"  }
            }
            $archivo = Listar-Versiones-FTP $carpeta
            if ($archivo -in "INVALIDO","REGRESAR") {
                Write-Host "Operacion cancelada." -ForegroundColor Yellow; continue
            }
        }

        switch ($opcion) {
            "1" { Instalar-IIS-Web $archivo $web_ftp $ssl }
            "2" { Instalar-Apache  $archivo $web_ftp $ssl }
            "3" { Instalar-Nginx   $archivo $web_ftp $ssl }
        }
    }
}

# -------------------------------------------------------------
# PEDIR PUERTOS
# -------------------------------------------------------------
function Pedir-Puerto {
    param($Nombre, $DefaultHTTP, $DefaultHTTPS)

    do {
        $ph = Read-Host "  Puerto HTTP para $Nombre [Enter = $DefaultHTTP]"
        if ([string]::IsNullOrWhiteSpace($ph)) { $ph = "$DefaultHTTP" }
    } while (-not ($ph -match '^\d+$' -and [int]$ph -ge 1 -and [int]$ph -le 65535))

    do {
        $ps = Read-Host "  Puerto HTTPS para $Nombre [Enter = $DefaultHTTPS]"
        if ([string]::IsNullOrWhiteSpace($ps)) { $ps = "$DefaultHTTPS" }
        if ($ps -eq $ph) { Write-Host "  HTTPS no puede ser igual a HTTP." -ForegroundColor Red }
    } while (-not ($ps -match '^\d+$' -and [int]$ps -ge 1 -and [int]$ps -le 65535 -and $ps -ne $ph))

    foreach ($p in @($ph, $ps)) {
        $usado = netstat -an | Select-String ":$p "
        if ($usado) { Write-Host "  ADVERTENCIA: el puerto $p ya esta en uso." -ForegroundColor Yellow }
    }

    return @([int]$ph, [int]$ps)
}

# -------------------------------------------------------------
# PREGUNTA SSL
# -------------------------------------------------------------
function Preguntar-SSL {
    while ($true) {
        $r = Read-Host "Desea activar SSL? [S/N] (0 para regresar)"
        if ($r -match '^[sS]$') { return "S" }
        if ($r -match '^[nN]$') { return "N" }
        if ($r -eq "0")          { return "REGRESAR" }
        Write-Host "Respuesta invalida." -ForegroundColor Red
    }
}

# -------------------------------------------------------------
# CERTIFICADO AUTOFIRMADO
# -------------------------------------------------------------
function Generar-SSL {
    param($Servicio)
    $cert_dir = "$SSL_DIR\$Servicio"
    New-Item -ItemType Directory -Force -Path $cert_dir | Out-Null

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        & openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
            -keyout "$cert_dir\server.key" `
            -out    "$cert_dir\server.crt" `
            -subj "/C=MX/ST=Sinaloa/O=Reprobados/CN=www.reprobados.com" 2>$null
        Write-Host "  OK Certificado PEM generado en $cert_dir" -ForegroundColor Green
    } else {
        $cert = New-SelfSignedCertificate `
            -DnsName "www.reprobados.com" `
            -CertStoreLocation "cert:\LocalMachine\My" `
            -NotAfter (Get-Date).AddDays(365) `
            -KeyAlgorithm RSA -KeyLength 2048 `
            -FriendlyName "Reprobados-$Servicio"

        $pwd_sec = ConvertTo-SecureString -String "reprobados" -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath "$cert_dir\server.pfx" -Password $pwd_sec | Out-Null
        Export-Certificate    -Cert $cert -FilePath "$cert_dir\server.crt" -Type CERT | Out-Null
        $cert.Thumbprint | Set-Content "$cert_dir\thumbprint.txt"
        Write-Host "  OK Certificado PFX generado en $cert_dir (pass: reprobados)" -ForegroundColor Green
    }
    return $cert_dir
}

# -------------------------------------------------------------
# PAGINA HTML DE ESTADO
# -------------------------------------------------------------
function Crear-Index {
    param($Servidor, $SSL, $Puerto, $DocRoot)
    New-Item -ItemType Directory -Force -Path $DocRoot | Out-Null
    $color = if ($SSL -eq "S") { "#27ae60" } else { "#2c3e50" }
    $msg   = if ($SSL -eq "S") { "SITIO SEGURO (HTTPS)" } else { "SITIO HTTP (Sin SSL)" }
    $html  = @"
<html>
<head><meta charset="UTF-8"></head>
<body style='font-family:Arial;text-align:center;background:$color;color:white;padding:50px;'>
  <div style='background:rgba(0,0,0,0.4);display:inline-block;padding:40px;border-radius:15px;border:3px solid white;'>
    <h1>SERVIDOR WEB: $Servidor</h1>
    <hr>
    <h2>$msg</h2>
    <p><b>Dominio:</b> www.reprobados.com</p>
    <p><b>Puerto:</b> $Puerto</p>
  </div>
</body>
</html>
"@
    Set-Content -Path "$DocRoot\index.html" -Value $html -Encoding UTF8
}

# -------------------------------------------------------------
# FIREWALL
# -------------------------------------------------------------
function Abrir-Puerto-Firewall {
    param($Puerto, $Nombre)
    New-NetFirewallRule -DisplayName "P7-$Nombre-$Puerto" `
        -Direction Inbound -Protocol TCP -LocalPort $Puerto `
        -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  Firewall: puerto $Puerto abierto." -ForegroundColor Cyan
}

# -------------------------------------------------------------
# NAVEGACION FTP - Fedora (FTPS explicito puerto 21)
# Usa curl.exe con --ssl-reqd --insecure
# -------------------------------------------------------------
function Listar-Versiones-FTP {
    param($Servicio)
    $url = "ftp://${FTP_SERVER}/${FTP_BASE}/${Servicio}/"
    Write-Host ""
    Write-Host "Conectando al FTP de Fedora ($FTP_SERVER) con FTPS..." -ForegroundColor Cyan
    Write-Host "Buscando instaladores en /$FTP_BASE/$Servicio/ ..."

    $raw = & curl.exe -s -l --ssl-reqd --insecure -u "${FTP_USER}:${FTP_PASS}" $url 2>&1

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        Write-Host "  ERROR: No se pudo listar el FTP." -ForegroundColor Red
        Write-Host "  Verifica que vsftpd este corriendo en Fedora con FTPS." -ForegroundColor Yellow
        return "INVALIDO"
    }

    $versiones = $raw -split "`n" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne "" -and $_ -notmatch '\.(sha256|md5)$' }

    if ($versiones.Count -eq 0) {
        Write-Host "  No se encontraron archivos en /$FTP_BASE/$Servicio/" -ForegroundColor Red
        Write-Host "  Ejecuta en Fedora:" -ForegroundColor Yellow
        Write-Host "    sudo mkdir -p /srv/ftp/$FTP_BASE/$Servicio" -ForegroundColor Yellow
        return "INVALIDO"
    }

    Write-Host "Versiones disponibles:"
    for ($i = 0; $i -lt $versiones.Count; $i++) {
        Write-Host "$($i+1)) $($versiones[$i])"
    }
    Write-Host "0) Regresar"

    $sel = Read-Host "Selecciona la version"
    if ($sel -eq "0") { return "REGRESAR" }
    if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $versiones.Count) {
        return $versiones[[int]$sel - 1]
    }
    return "INVALIDO"
}

# -------------------------------------------------------------
# DESCARGA DESDE FTP DE FEDORA + VALIDACION SHA256
# Usa curl.exe con --ssl-reqd --insecure (FTPS explicito)
# -------------------------------------------------------------
function Descargar-Y-Validar {
    param($Servicio, $Archivo)
    $url_base = "ftp://${FTP_SERVER}/${FTP_BASE}/${Servicio}/"
    $destino  = "$env:TEMP\$Archivo"

    Write-Host "Descargando $Archivo desde FTP de Fedora (FTPS)..." -ForegroundColor Cyan

    & curl.exe -s --ssl-reqd --insecure -u "${FTP_USER}:${FTP_PASS}" "${url_base}${Archivo}" -o $destino

    if (-not (Test-Path $destino) -or (Get-Item $destino).Length -eq 0) {
        Write-Host "  ERROR: Descarga fallida o archivo vacio." -ForegroundColor Red
        return $false
    }

    $tamano = [math]::Round((Get-Item $destino).Length / 1MB, 2)
    Write-Host "  Descarga completada: $tamano MB" -ForegroundColor Green

    # Intentar SHA256
    $sha_dest = "$env:TEMP\${Archivo}.sha256"
    & curl.exe -s --ssl-reqd --insecure -u "${FTP_USER}:${FTP_PASS}" "${url_base}${Archivo}.sha256" -o $sha_dest 2>$null

    if ((Test-Path $sha_dest) -and (Get-Item $sha_dest).Length -gt 0) {
        $hash_remoto = (Get-Content $sha_dest -Raw).Trim().Split(" ")[0].ToLower()
        $hash_local  = (Get-FileHash $destino -Algorithm SHA256).Hash.ToLower()
        Remove-Item $sha_dest -Force -ErrorAction SilentlyContinue

        if ($hash_remoto -eq $hash_local) {
            Write-Host "  OK Integridad SHA256 verificada." -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ERROR DE INTEGRIDAD SHA256. Abortando." -ForegroundColor Red
            Remove-Item $destino -Force -ErrorAction SilentlyContinue
            return $false
        }
    }

    # Fallback MD5
    $md5_dest = "$env:TEMP\${Archivo}.md5"
    & curl.exe -s --ssl-reqd --insecure -u "${FTP_USER}:${FTP_PASS}" "${url_base}${Archivo}.md5" -o $md5_dest 2>$null

    if ((Test-Path $md5_dest) -and (Get-Item $md5_dest).Length -gt 0) {
        $hash_remoto = (Get-Content $md5_dest -Raw).Trim().Split(" ")[0].ToLower()
        $hash_local  = (Get-FileHash $destino -Algorithm MD5).Hash.ToLower()
        Remove-Item $md5_dest -Force -ErrorAction SilentlyContinue

        if ($hash_remoto -eq $hash_local) {
            Write-Host "  OK Integridad MD5 verificada." -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ERROR DE INTEGRIDAD MD5. Abortando." -ForegroundColor Red
            Remove-Item $destino -Force -ErrorAction SilentlyContinue
            return $false
        }
    }

    Write-Host "  ADVERTENCIA: Sin .sha256 ni .md5. Se omite validacion." -ForegroundColor Yellow
    return $true
}

# -------------------------------------------------------------
# EXTRAER ZIP
# -------------------------------------------------------------
function Extraer-Zip {
    param($RutaZip, $Destino)
    New-Item -ItemType Directory -Force -Path $Destino | Out-Null
    Expand-Archive -Path $RutaZip -DestinationPath $Destino -Force

    $hijos = Get-ChildItem $Destino
    if ($hijos.Count -eq 1 -and $hijos[0].PSIsContainer) {
        $sub = $hijos[0].FullName
        Get-ChildItem "$sub\*" | Move-Item -Destination $Destino -Force -ErrorAction SilentlyContinue
        Remove-Item $sub -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  OK Extraido en $Destino" -ForegroundColor Green
}

# =============================================================
# IIS WEB
# =============================================================
function Instalar-IIS-Web {
    param($Archivo, $WebFTP, $SSL)
    Write-Host ""
    Write-Host "--- INSTALANDO IIS WEB ---" -ForegroundColor Cyan

    Write-Host "Instalando IIS..."
    Install-WindowsFeature Web-Server -IncludeManagementTools | Out-Null
    Import-Module WebAdministration -ErrorAction SilentlyContinue

    $puertos      = Pedir-Puerto "IIS" 80 443
    $puerto_http  = $puertos[0]
    $puerto_https = $puertos[1]

    Get-Website | ForEach-Object {
        Stop-Website   -Name $_.Name -ErrorAction SilentlyContinue
        Remove-Website -Name $_.Name -ErrorAction SilentlyContinue
    }

    $siteName = "SitioIIS_P7"
    $sitePath = "C:\inetpub\wwwroot\$siteName"
    New-Item -ItemType Directory -Force -Path $sitePath | Out-Null

    $puerto_display = if ($SSL -eq "S") { $puerto_https } else { $puerto_http }
    Crear-Index "IIS" $SSL $puerto_display $sitePath

    if ($SSL -eq "S") {
        $chocoExe = "C:\ProgramData\chocolatey\bin\choco.exe"
        if (-not (Test-Path $chocoExe)) {
            Write-Host "Instalando Chocolatey..."
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        Write-Host "Instalando URL Rewrite para IIS..."
        & $chocoExe install urlrewrite -y --force *>$null
        iisreset /restart | Out-Null

        Write-Host "Generando certificado SSL..."
        $cert = New-SelfSignedCertificate `
            -DnsName "www.reprobados.com" `
            -CertStoreLocation "cert:\LocalMachine\My" `
            -NotAfter (Get-Date).AddDays(365)

        New-Website    -Name $siteName -Port $puerto_http -PhysicalPath $sitePath -Force | Out-Null
        New-WebBinding -Name $siteName -Protocol "https"  -Port $puerto_https -IPAddress "*"

        Push-Location IIS:\SslBindings
        Remove-Item -Path "*!$puerto_https" -Force -ErrorAction SilentlyContinue
        Get-Item "cert:\LocalMachine\My\$($cert.Thumbprint)" | New-Item -Path "*!$puerto_https" -Force | Out-Null
        Pop-Location

        $webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="HTTP a HTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions><add input="{HTTPS}" pattern="^OFF`$" /></conditions>
          <action type="Redirect" url="https://{HTTP_HOST}:$puerto_https/{R:1}" redirectType="Permanent" />
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
        Set-Content -Path "$sitePath\web.config" -Value $webConfig -Force

        Abrir-Puerto-Firewall $puerto_https "IIS-HTTPS"
        $script:SERVICIOS_VERIFICAR   += "IIS-SSL|W3SVC|$puerto_https|https"
        $script:RESUMEN_INSTALACIONES += "IIS Web | SSL:S | HTTP:$puerto_http -> HTTPS:$puerto_https | HSTS activo"
    } else {
        New-Website -Name $siteName -Port $puerto_http -PhysicalPath $sitePath -Force | Out-Null
        $script:RESUMEN_INSTALACIONES += "IIS Web | SSL:N | HTTP:$puerto_http"
    }

    Abrir-Puerto-Firewall $puerto_http "IIS-HTTP"
    $script:SERVICIOS_VERIFICAR += "IIS|W3SVC|$puerto_http|http"
    Start-Website -Name $siteName -ErrorAction SilentlyContinue

    Write-Host "OK IIS Web configurado." -ForegroundColor Green
    Write-Host "   Accede en: http://127.0.0.1:$puerto_http"
}

# =============================================================
# APACHE HTTPD
# =============================================================
function Instalar-Apache {
    param($Archivo, $WebFTP, $SSL)
    Write-Host ""
    Write-Host "--- INSTALANDO APACHE ---" -ForegroundColor Cyan

    Stop-Service "Apache2.4" -Force -ErrorAction SilentlyContinue
    sc.exe delete "Apache2.4" | Out-Null
    if (Test-Path $APACHE_DIR) { Remove-Item $APACHE_DIR -Recurse -Force -ErrorAction SilentlyContinue }

    $puertos      = Pedir-Puerto "Apache" 8080 8443
    $puerto_http  = $puertos[0]
    $puerto_https = $puertos[1]

    if ($WebFTP -eq "FTP") {
        if (-not (Descargar-Y-Validar "Apache" $Archivo)) { return }
        Extraer-Zip "$env:TEMP\$Archivo" $APACHE_DIR
    } else {
        Write-Host "Descargando Apache desde Internet..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile(
            "https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.62-240904-win64-VS17.zip",
            "$env:TEMP\apache.zip")
        Extraer-Zip "$env:TEMP\apache.zip" $APACHE_DIR
    }

    $docroot  = "$APACHE_DIR\htdocs"
    $conf_dir = "$APACHE_DIR\conf\extra"
    New-Item -ItemType Directory -Force -Path $conf_dir | Out-Null

    $puerto_display = if ($SSL -eq "S") { $puerto_https } else { $puerto_http }
    Crear-Index "Apache" $SSL $puerto_display $docroot

    $httpd_conf = "$APACHE_DIR\conf\httpd.conf"
    if (Test-Path $httpd_conf) {
        $conf = Get-Content $httpd_conf -Raw
        $conf = $conf -replace 'Define SRVROOT ".*"',                        "Define SRVROOT `"$($APACHE_DIR -replace '\\','/')`""
        $conf = $conf -replace '(?m)^Listen 80$',                             "Listen $puerto_http"
        $conf = $conf -replace '(?m)^#?(LoadModule rewrite_module)',          'LoadModule rewrite_module'
        $conf = $conf -replace '(?m)^#?(LoadModule headers_module)',          'LoadModule headers_module'
        $conf | Set-Content $httpd_conf
    }

    if ($SSL -eq "S") {
        $cert_dir = Generar-SSL "apache"

        $conf = Get-Content $httpd_conf -Raw
        $conf = $conf -replace '(?m)^#?(LoadModule ssl_module)',              'LoadModule ssl_module'
        $conf = $conf -replace '(?m)^#?(LoadModule socache_shmcb_module)',    'LoadModule socache_shmcb_module'
        $conf = $conf -replace '(?m)^#?(Include conf/extra/httpd-ssl\.conf)', 'Include conf/extra/httpd-ssl.conf'
        $conf | Set-Content $httpd_conf

        $apacheDir_unix = $APACHE_DIR -replace '\\','/'
        $certDir_unix   = $cert_dir   -replace '\\','/'

        $ssl_conf = @"
Listen $puerto_https

SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
SSLProtocol all -SSLv3
SSLPassPhraseDialog builtin
SSLSessionCache "shmcb:$apacheDir_unix/logs/ssl_scache(512000)"
SSLSessionCacheTimeout 300

<VirtualHost *:$puerto_http>
    ServerName www.reprobados.com
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}:$puerto_https%{REQUEST_URI} [L,R=301]
</VirtualHost>

<VirtualHost *:$puerto_https>
    ServerName www.reprobados.com
    DocumentRoot "$apacheDir_unix/htdocs"
    SSLEngine on
    SSLCertificateFile    "$certDir_unix/server.crt"
    SSLCertificateKeyFile "$certDir_unix/server.key"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
"@
        Set-Content "$conf_dir\httpd-ssl.conf" $ssl_conf

        Abrir-Puerto-Firewall $puerto_https "Apache-HTTPS"
        $script:SERVICIOS_VERIFICAR   += "Apache-SSL|Apache2.4|$puerto_https|https"
        $script:RESUMEN_INSTALACIONES += "Apache  | SSL:S | HTTP:$puerto_http -> HTTPS:$puerto_https | HSTS activo"
    } else {
        $script:RESUMEN_INSTALACIONES += "Apache  | SSL:N | HTTP:$puerto_http"
    }

    Abrir-Puerto-Firewall $puerto_http "Apache-HTTP"
    $script:SERVICIOS_VERIFICAR += "Apache|Apache2.4|$puerto_http|http"

    $httpd = "$APACHE_DIR\bin\httpd.exe"
    if (Test-Path $httpd) {
        & $httpd -k install -n "Apache2.4" 2>$null
        Start-Service "Apache2.4" -ErrorAction SilentlyContinue
        Set-Service   "Apache2.4" -StartupType Automatic -ErrorAction SilentlyContinue
        Write-Host "OK Apache instalado como servicio Windows." -ForegroundColor Green
    } else {
        Write-Host "ADVERTENCIA: httpd.exe no encontrado en $APACHE_DIR\bin\" -ForegroundColor Yellow
    }

    Write-Host "OK Apache listo. Accede en http://127.0.0.1:$puerto_http"
}

# =============================================================
# NGINX
# =============================================================
function Instalar-Nginx {
    param($Archivo, $WebFTP, $SSL)
    Write-Host ""
    Write-Host "--- INSTALANDO NGINX ---" -ForegroundColor Cyan

    taskkill /F /IM nginx.exe 2>$null | Out-Null
    if (Test-Path $NGINX_DIR) { Remove-Item $NGINX_DIR -Recurse -Force -ErrorAction SilentlyContinue }

    $puertos      = Pedir-Puerto "Nginx" 8081 8444
    $puerto_http  = $puertos[0]
    $puerto_https = $puertos[1]

    if ($WebFTP -eq "FTP") {
        if (-not (Descargar-Y-Validar "Nginx" $Archivo)) { return }
        Extraer-Zip "$env:TEMP\$Archivo" $NGINX_DIR
    } else {
        Write-Host "Descargando Nginx desde Internet..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile("https://nginx.org/download/nginx-1.26.2.zip","$env:TEMP\nginx.zip")
        Extraer-Zip "$env:TEMP\nginx.zip" $NGINX_DIR
    }

    $docroot        = "$NGINX_DIR\html"
    $puerto_display = if ($SSL -eq "S") { $puerto_https } else { $puerto_http }
    Crear-Index "Nginx" $SSL $puerto_display $docroot

    if ($SSL -eq "S") {
        $cert_dir     = Generar-SSL "nginx"
        $certDir_unix = $cert_dir -replace '\\','/'

        $nginx_conf = @"
worker_processes 1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;

    server {
        listen $puerto_http;
        server_name www.reprobados.com;
        return 301 https://`$host:$puerto_https`$request_uri;
    }

    server {
        listen $puerto_https ssl;
        server_name www.reprobados.com;

        ssl_certificate     "$certDir_unix/server.crt";
        ssl_certificate_key "$certDir_unix/server.key";
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        root  html;
        index index.html;
    }
}
"@
        Abrir-Puerto-Firewall $puerto_https "Nginx-HTTPS"
        $script:SERVICIOS_VERIFICAR   += "Nginx-SSL|nginx|$puerto_https|https"
        $script:RESUMEN_INSTALACIONES += "Nginx   | SSL:S | HTTP:$puerto_http -> HTTPS:$puerto_https | HSTS activo"
    } else {
        $nginx_conf = @"
worker_processes 1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;
    server {
        listen $puerto_http;
        server_name www.reprobados.com;
        root  html;
        index index.html;
    }
}
"@
        $script:RESUMEN_INSTALACIONES += "Nginx   | SSL:N | HTTP:$puerto_http"
    }

    Set-Content "$NGINX_DIR\conf\nginx.conf" $nginx_conf -Encoding ASCII

    Abrir-Puerto-Firewall $puerto_http "Nginx-HTTP"
    $script:SERVICIOS_VERIFICAR += "Nginx|nginx|$puerto_http|http"

    Start-Process "$NGINX_DIR\nginx.exe" -WorkingDirectory $NGINX_DIR -WindowStyle Hidden
    Write-Host "OK Nginx iniciado en segundo plano." -ForegroundColor Green
    Write-Host "   Accede en http://127.0.0.1:$puerto_http"
}

# =============================================================
# VERIFICACION
# =============================================================
function Verificar-HTTP {
    param($Nombre, $Servicio, $Puerto, $Proto)

    $estado = "INACTIVO"
    if ($Servicio -eq "nginx") {
        $proc  = Get-Process nginx -ErrorAction SilentlyContinue
        $estado = if ($proc) { "ACTIVO" } else { "INACTIVO" }
    } else {
        $svc   = Get-Service $Servicio -ErrorAction SilentlyContinue
        $estado = if ($svc -and $svc.Status -eq "Running") { "ACTIVO" } else { "INACTIVO" }
    }

    $resp = "N/A"
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $r    = Invoke-WebRequest "${Proto}://127.0.0.1:${Puerto}" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $resp = $r.StatusCode
    } catch {
        if ($_.Exception.Response) { $resp = [int]$_.Exception.Response.StatusCode }
    }

    Write-Host "  [$Nombre] Proceso:$estado | Puerto:$Puerto ($Proto) -> HTTP $resp"

    if ($Proto -eq "https") {
        try {
            $h    = Invoke-WebRequest "${Proto}://127.0.0.1:${Puerto}" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            $hsts = $h.Headers["Strict-Transport-Security"]
            if ($hsts) { Write-Host "  [$Nombre] HSTS: OK ($hsts)" -ForegroundColor Green }
            else        { Write-Host "  [$Nombre] HSTS: no encontrado" -ForegroundColor Yellow }
        } catch {}
    }
}

# =============================================================
# RESUMEN
# =============================================================
function Mostrar-Resumen {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Magenta
    Write-Host "         RESUMEN AUTOMATIZADO DE SERVICIOS               " -ForegroundColor Magenta
    Write-Host "==========================================================" -ForegroundColor Magenta

    if ($script:RESUMEN_INSTALACIONES.Count -eq 0) {
        Write-Host "  No se ha instalado ningun servicio en esta sesion."
    } else {
        Write-Host ""
        Write-Host "-- Servicios instalados ----------------------------------"
        foreach ($r in $script:RESUMEN_INSTALACIONES) { Write-Host "  -> $r" -ForegroundColor Cyan }
    }

    Write-Host ""
    Write-Host "-- Verificacion activa -----------------------------------"
    if ($script:SERVICIOS_VERIFICAR.Count -eq 0) {
        Write-Host "  (sin servicios registrados aun)"
    } else {
        foreach ($entrada in $script:SERVICIOS_VERIFICAR) {
            $p = $entrada -split "\|"
            Verificar-HTTP $p[0] $p[1] $p[2] $p[3]
        }
    }

    Write-Host ""
    Write-Host "-- Puertos activos en el sistema ------------------------"
    netstat -an | Select-String "LISTENING" | ForEach-Object {
        ($_ -split "\s+")[2]
    } | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }

    Write-Host "==========================================================" -ForegroundColor Magenta
}

# =============================================================
# PUNTO DE ENTRADA
# =============================================================
Main
