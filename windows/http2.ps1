# =============================================================
#   PRACTICA 7 - Orquestador de Instalacion con SSL/TLS
#   Sistema: Windows Server 2019
#   Servicios: Apache httpd, Nginx, Tomcat, FileZilla Server
#
#   Ejecutar como Administrador:
#   powershell -ExecutionPolicy Bypass -File practica7_windows.ps1
# =============================================================

#Requires -RunAsAdministrator

# -------------------------------------------------------------
# VARIABLES GLOBALES
# -------------------------------------------------------------
$FTP_SERVER   = "192.168.114.129"
$FTP_USER     = "repositorio"
$FTP_PASS     = "Hola1234."
$FTP_BASE     = "repositorio/Windows"

$RESUMEN_INSTALACIONES = @()
$SERVICIOS_VERIFICAR   = @()   # "nombre|servicio_windows|puerto|proto"

# Rutas base de instalacion
$BASE_DIR     = "C:\Servicios"
$APACHE_DIR   = "$BASE_DIR\Apache"
$NGINX_DIR    = "$BASE_DIR\Nginx"
$TOMCAT_DIR   = "$BASE_DIR\Tomcat"
$FZ_DIR       = "$BASE_DIR\FileZilla"
$SSL_DIR      = "$BASE_DIR\SSL"

# -------------------------------------------------------------
# MENU PRINCIPAL
# -------------------------------------------------------------
function Main {
    while ($true) {
        Write-Host ""
        Write-Host "=========================================================="
        Write-Host "   PRACTICA 7 - ORQUESTADOR DE SERVICIOS (WINDOWS 2019)  "
        Write-Host "=========================================================="
        Write-Host " 1) Apache (httpd)"
        Write-Host " 2) Nginx"
        Write-Host " 3) Tomcat"
        Write-Host " 4) FileZilla Server (FTP)"
        Write-Host " 5) Ver Resumen de Instalaciones"
        Write-Host " 6) Preparar repositorio FTP local"
        Write-Host " 0) Salir"
        Write-Host "=========================================================="
        $opcion = Read-Host "Selecciona una opcion"

        switch ($opcion) {
            "0" { Mostrar-Resumen; Write-Host "Saliendo..."; return }
            "5" { Mostrar-Resumen; continue }
            "6" { Preparar-Repositorio-FTP; continue }
            { $_ -in "1","2","3","4" } { }
            default { Write-Host "Opcion invalida."; continue }
        }

        Write-Host ""
        Write-Host "De donde deseas instalar?"
        Write-Host " 1) WEB (descarga directa)"
        Write-Host " 2) FTP (repositorio privado)"
        Write-Host " 0) Regresar"
        $origen = Read-Host "Selecciona origen"
        if ($origen -eq "0") { continue }
        $web_ftp = if ($origen -eq "2") { "FTP" } else { "WEB" }

        $ssl = Preguntar-SSL
        if ($ssl -eq "REGRESAR") { continue }

        $archivo = ""
        if ($web_ftp -eq "FTP") {
            $carpeta = switch ($opcion) {
                "1" { "Apache" }
                "2" { "Nginx"  }
                "3" { "Tomcat" }
                "4" { "FileZilla" }
            }
            $archivo = Listar-Versiones-FTP $carpeta
            if ($archivo -in "INVALIDO","REGRESAR") {
                Write-Host "Operacion cancelada."; continue
            }
        }

        switch ($opcion) {
            "1" { Instalar-Apache  $archivo $web_ftp $ssl }
            "2" { Instalar-Nginx   $archivo $web_ftp $ssl }
            "3" { Instalar-Tomcat  $archivo $web_ftp $ssl }
            "4" { Instalar-FileZilla $archivo $web_ftp $ssl }
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
        if ([string]::IsNullOrWhiteSpace($ph)) { $ph = $DefaultHTTP }
    } while (-not ($ph -match '^\d+$' -and [int]$ph -ge 1 -and [int]$ph -le 65535))

    do {
        $ps = Read-Host "  Puerto HTTPS para $Nombre [Enter = $DefaultHTTPS]"
        if ([string]::IsNullOrWhiteSpace($ps)) { $ps = $DefaultHTTPS }
        if ($ps -eq $ph) { Write-Host "  HTTPS no puede ser igual a HTTP." }
    } while (-not ($ps -match '^\d+$' -and [int]$ps -ge 1 -and [int]$ps -le 65535 -and $ps -ne $ph))

    foreach ($p in @($ph, $ps)) {
        $usado = netstat -an | Select-String ":$p "
        if ($usado) { Write-Host "  ADVERTENCIA: el puerto $p ya esta en uso." }
    }

    return @([int]$ph, [int]$ps)
}

# -------------------------------------------------------------
# NAVEGACION FTP (no interactiva con WebClient / curl)
# Reto Tecnico: sin GUI, usando WebClient de PowerShell
# -------------------------------------------------------------
function Listar-Versiones-FTP {
    param($Servicio)
    $url = "ftp://${FTP_SERVER}/${FTP_BASE}/${Servicio}/"
    Write-Host ""
    Write-Host "Buscando instaladores de $Servicio en $url ..."

    try {
        $request = [System.Net.FtpWebRequest]::Create($url)
        $request.Method      = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $request.Credentials = New-Object System.Net.NetworkCredential($FTP_USER, $FTP_PASS)
        $request.EnableSsl   = $true
        $request.KeepAlive   = $false

        # Aceptar certificado autofirmado
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        $response = $request.GetResponse()
        $reader   = New-Object System.IO.StreamReader($response.GetResponseStream())
        $contenido = $reader.ReadToEnd()
        $reader.Close(); $response.Close()

        $versiones = $contenido -split "`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne "" -and $_ -notmatch '\.(sha256|md5)$' }
    }
    catch {
        Write-Host "Error FTPS, intentando FTP plano..."
        try {
            $request2 = [System.Net.FtpWebRequest]::Create($url)
            $request2.Method      = [System.Net.WebRequestMethods+Ftp]::ListDirectory
            $request2.Credentials = New-Object System.Net.NetworkCredential($FTP_USER, $FTP_PASS)
            $request2.EnableSsl   = $false

            $response2  = $request2.GetResponse()
            $reader2    = New-Object System.IO.StreamReader($response2.GetResponseStream())
            $contenido2 = $reader2.ReadToEnd()
            $reader2.Close(); $response2.Close()

            $versiones = $contenido2 -split "`n" |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -ne "" -and $_ -notmatch '\.(sha256|md5)$' }
        }
        catch {
            Write-Host "No se encontraron versiones para $Servicio."
            Write-Host "Verifica que existan archivos en el FTP."
            return "INVALIDO"
        }
    }

    if ($versiones.Count -eq 0) {
        Write-Host "No se encontraron versiones para $Servicio."
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
# DESCARGA Y VALIDACION DE INTEGRIDAD
# Reto Tecnico: WebClient para descarga no interactiva
# -------------------------------------------------------------
function Descargar-Y-Validar {
    param($Servicio, $Archivo)
    $url_base = "ftp://${FTP_SERVER}/${FTP_BASE}/${Servicio}/"
    $destino  = "$env:TEMP\$Archivo"

    Write-Host "Descargando $Archivo desde FTP..."

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $wc = New-Object System.Net.WebClient
    $wc.Credentials = New-Object System.Net.NetworkCredential($FTP_USER, $FTP_PASS)

    try { $wc.DownloadFile("${url_base}${Archivo}", $destino) }
    catch { Write-Host "ERROR: No se pudo descargar $Archivo."; return $false }

    # Intentar SHA256
    $sha_dest = "$env:TEMP\${Archivo}.sha256"
    try {
        $wc.DownloadFile("${url_base}${Archivo}.sha256", $sha_dest)
        $hash_remoto = (Get-Content $sha_dest).Split(" ")[0].Trim().ToLower()
        $hash_local  = (Get-FileHash $destino -Algorithm SHA256).Hash.ToLower()
        if ($hash_remoto -eq $hash_local) {
            Write-Host "OK Integridad SHA256 verificada."
            Remove-Item $sha_dest -Force -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-Host "ERROR DE INTEGRIDAD SHA256. Abortando."
            Remove-Item $destino,$sha_dest -Force -ErrorAction SilentlyContinue
            return $false
        }
    } catch { Remove-Item $sha_dest -Force -ErrorAction SilentlyContinue }

    # Fallback MD5
    $md5_dest = "$env:TEMP\${Archivo}.md5"
    try {
        $wc.DownloadFile("${url_base}${Archivo}.md5", $md5_dest)
        $hash_remoto = (Get-Content $md5_dest).Split(" ")[0].Trim().ToLower()
        $hash_local  = (Get-FileHash $destino -Algorithm MD5).Hash.ToLower()
        if ($hash_remoto -eq $hash_local) {
            Write-Host "OK Integridad MD5 verificada."
            Remove-Item $md5_dest -Force -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-Host "ERROR DE INTEGRIDAD MD5. Abortando."
            Remove-Item $destino,$md5_dest -Force -ErrorAction SilentlyContinue
            return $false
        }
    } catch { Remove-Item $md5_dest -Force -ErrorAction SilentlyContinue }

    Write-Host "ADVERTENCIA: Sin .sha256 ni .md5. Se omite validacion."
    return $true
}

# -------------------------------------------------------------
# INSTALACION DESDE PAQUETE LOCAL (silenciosa)
# -------------------------------------------------------------
function Instalar-Paquete-Local {
    param($Archivo, $Destino)
    $ruta = "$env:TEMP\$Archivo"
    Write-Host "Instalando $Archivo ..."

    switch -Wildcard ($Archivo) {
        "*.msi" {
            Start-Process msiexec.exe -ArgumentList "/i `"$ruta`" /quiet /norestart INSTALLDIR=`"$Destino`"" -Wait
        }
        "*.exe" {
            Start-Process $ruta -ArgumentList "/S /D=$Destino" -Wait
        }
        "*.zip" {
            New-Item -ItemType Directory -Force -Path $Destino | Out-Null
            Expand-Archive -Path $ruta -DestinationPath $Destino -Force
            Write-Host "OK Extraido en $Destino"
        }
        "*.tar.gz" {
            New-Item -ItemType Directory -Force -Path $Destino | Out-Null
            tar -xzf $ruta -C $Destino --strip-components=1
            Write-Host "OK Extraido en $Destino"
        }
        default {
            Write-Host "ERROR: Formato no reconocido: $Archivo"
            return $false
        }
    }
    return $true
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
        Write-Host "Respuesta invalida."
    }
}

# -------------------------------------------------------------
# CERTIFICADO AUTOFIRMADO (PowerShell nativo, sin openssl)
# -------------------------------------------------------------
function Generar-SSL {
    param($Servicio)
    $cert_dir = "$SSL_DIR\$Servicio"
    New-Item -ItemType Directory -Force -Path $cert_dir | Out-Null

    $cert = New-SelfSignedCertificate `
        -DnsName "www.reprobados.com" `
        -CertStoreLocation "cert:\LocalMachine\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyAlgorithm RSA -KeyLength 2048 `
        -FriendlyName "Reprobados-$Servicio"

    # Exportar PFX (con clave privada)
    $pwd = ConvertTo-SecureString -String "reprobados" -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath "$cert_dir\server.pfx" -Password $pwd | Out-Null

    # Exportar CRT (solo certificado publico)
    Export-Certificate -Cert $cert -FilePath "$cert_dir\server.crt" -Type CERT | Out-Null

    Write-Host "OK Certificado autofirmado generado en $cert_dir"
    return $cert_dir
}

# -------------------------------------------------------------
# PAGINA HTML SIMPLE
# -------------------------------------------------------------
function Crear-Index {
    param($Servidor, $Puerto, $DocRoot)
    New-Item -ItemType Directory -Force -Path $DocRoot | Out-Null
    $html = @"
<html>
<head><meta charset="UTF-8"></head>
<body>
    <p>$Servidor</p>
    <p>Puerto: $Puerto</p>
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
    New-NetFirewallRule -DisplayName "Practica7-$Nombre-$Puerto" `
        -Direction Inbound -Protocol TCP -LocalPort $Puerto `
        -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  Firewall: puerto $Puerto abierto."
}

# -------------------------------------------------------------
# APACHE HTTPD PARA WINDOWS
# Descarga desde Apache Lounge (zip) o desde FTP
# -------------------------------------------------------------
function Instalar-Apache {
    param($Archivo, $WebFTP, $SSL)

    Write-Host ""
    Write-Host "-- Configuracion de puertos para Apache ---------"
    $puertos = Pedir-Puerto "Apache" 80 443
    $puerto_http  = $puertos[0]
    $puerto_https = $puertos[1]

    if ($WebFTP -eq "FTP") {
        if (-not (Descargar-Y-Validar "Apache" $Archivo)) { return }
        if (-not (Instalar-Paquete-Local $Archivo $APACHE_DIR)) { return }
    } else {
        Write-Host "Descargando Apache desde Apache Lounge..."
        $url = "https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.62-240904-win64-VS17.zip"
        $wc  = New-Object System.Net.WebClient
        $wc.DownloadFile($url, "$env:TEMP\apache.zip")
        New-Item -ItemType Directory -Force -Path $APACHE_DIR | Out-Null
        Expand-Archive "$env:TEMP\apache.zip" -DestinationPath $APACHE_DIR -Force
        # Apache Lounge extrae en subcarpeta Apache24
        $sub = Get-ChildItem $APACHE_DIR -Directory | Select-Object -First 1
        if ($sub) {
            Get-ChildItem "$($sub.FullName)\*" | Move-Item -Destination $APACHE_DIR -Force -ErrorAction SilentlyContinue
            Remove-Item $sub.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $docroot  = "$APACHE_DIR\htdocs"
    $conf_dir = "$APACHE_DIR\conf\extra"
    New-Item -ItemType Directory -Force -Path $conf_dir | Out-Null

    $puerto_display = if ($SSL -eq "S") { $puerto_https } else { $puerto_http }
    Crear-Index "Apache (httpd)" $puerto_display $docroot

    # Configuracion principal
    $httpd_conf = "$APACHE_DIR\conf\httpd.conf"
    if (Test-Path $httpd_conf) {
        (Get-Content $httpd_conf) -replace '^Listen 80$',"Listen $puerto_http" |
            Set-Content $httpd_conf
        (Get-Content $httpd_conf) -replace 'SRVROOT ".*"',"SRVROOT `"$APACHE_DIR`"" |
            Set-Content $httpd_conf
    }

    if ($SSL -eq "S") {
        $cert_dir = Generar-SSL "apache"
        # Habilitar mod_ssl en httpd.conf
        if (Test-Path $httpd_conf) {
            (Get-Content $httpd_conf) -replace '#LoadModule ssl_module','LoadModule ssl_module' |
                Set-Content $httpd_conf
            (Get-Content $httpd_conf) -replace '#Include conf/extra/httpd-ssl.conf','Include conf/extra/httpd-ssl.conf' |
                Set-Content $httpd_conf
        }
        $ssl_conf = @"
Listen $puerto_https
<VirtualHost *:$puerto_https>
    ServerName www.reprobados.com
    DocumentRoot "$docroot"
    SSLEngine on
    SSLCertificateFile    "$cert_dir\server.crt"
    SSLCertificateKeyFile "$cert_dir\server.pfx"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
"@
        Set-Content "$conf_dir\reprobados_ssl.conf" $ssl_conf
        Abrir-Puerto-Firewall $puerto_https "Apache-HTTPS"
        $script:SERVICIOS_VERIFICAR += "Apache-SSL|Apache2.4|${puerto_https}|https"
    }

    Abrir-Puerto-Firewall $puerto_http "Apache-HTTP"
    $script:SERVICIOS_VERIFICAR += "Apache|Apache2.4|${puerto_http}|http"

    # Instalar y arrancar como servicio Windows
    $httpd = "$APACHE_DIR\bin\httpd.exe"
    if (Test-Path $httpd) {
        & $httpd -k install -n "Apache2.4" 2>$null
        Start-Service "Apache2.4" -ErrorAction SilentlyContinue
        Set-Service  "Apache2.4" -StartupType Automatic -ErrorAction SilentlyContinue
    } else {
        Write-Host "ADVERTENCIA: httpd.exe no encontrado en $APACHE_DIR\bin\"
    }

    $script:RESUMEN_INSTALACIONES += "Apache  | SSL:$SSL | HTTP:$puerto_http  HTTPS:$puerto_https"
    Write-Host "OK Apache instalado. Accede en http://127.0.0.1:$puerto_http"
}

# -------------------------------------------------------------
# NGINX PARA WINDOWS
# -------------------------------------------------------------
function Instalar-Nginx {
    param($Archivo, $WebFTP, $SSL)

    Write-Host ""
    Write-Host "-- Configuracion de puertos para Nginx ----------"
    $puertos = Pedir-Puerto "Nginx" 8081 8444
    $puerto_http  = $puertos[0]
    $puerto_https = $puertos[1]

    if ($WebFTP -eq "FTP") {
        if (-not (Descargar-Y-Validar "Nginx" $Archivo)) { return }
        if (-not (Instalar-Paquete-Local $Archivo $NGINX_DIR)) { return }
    } else {
        Write-Host "Descargando Nginx desde nginx.org..."
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile("https://nginx.org/download/nginx-1.26.2.zip", "$env:TEMP\nginx.zip")
        New-Item -ItemType Directory -Force -Path $NGINX_DIR | Out-Null
        Expand-Archive "$env:TEMP\nginx.zip" -DestinationPath $NGINX_DIR -Force
        $sub = Get-ChildItem $NGINX_DIR -Directory | Select-Object -First 1
        if ($sub) {
            Get-ChildItem "$($sub.FullName)\*" | Move-Item -Destination $NGINX_DIR -Force -ErrorAction SilentlyContinue
            Remove-Item $sub.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $docroot = "$NGINX_DIR\html"
    $puerto_display = if ($SSL -eq "S") { $puerto_https } else { $puerto_http }
    Crear-Index "Nginx" $puerto_display $docroot

    if ($SSL -eq "S") {
        $cert_dir = Generar-SSL "nginx"
        $nginx_conf = @"
worker_processes 1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    server {
        listen $puerto_http;
        server_name www.reprobados.com;
        return 301 https://`$host:$puerto_https`$request_uri;
    }
    server {
        listen $puerto_https ssl;
        server_name www.reprobados.com;
        ssl_certificate     "$cert_dir\server.crt";
        ssl_certificate_key "$cert_dir\server.pfx";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        root  html;
        index index.html;
    }
}
"@
        Abrir-Puerto-Firewall $puerto_https "Nginx-HTTPS"
        $script:SERVICIOS_VERIFICAR += "Nginx-SSL|nginx|${puerto_https}|https"
    } else {
        $nginx_conf = @"
worker_processes 1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    server {
        listen $puerto_http;
        server_name www.reprobados.com;
        root  html;
        index index.html;
    }
}
"@
    }

    Set-Content "$NGINX_DIR\conf\nginx.conf" $nginx_conf

    Abrir-Puerto-Firewall $puerto_http "Nginx-HTTP"
    $script:SERVICIOS_VERIFICAR += "Nginx|nginx|${puerto_http}|http"

    # Nginx en Windows no tiene instalador de servicio nativo
    # Se usa NSSM (Non-Sucking Service Manager) o se corre directo
    $nssm = "$BASE_DIR\nssm\nssm.exe"
    if (Test-Path $nssm) {
        & $nssm install "nginx" "$NGINX_DIR\nginx.exe" 2>$null
        & $nssm set nginx AppDirectory $NGINX_DIR 2>$null
        Start-Service "nginx" -ErrorAction SilentlyContinue
    } else {
        Write-Host "NOTA: Nginx no tiene servicio Windows nativo."
        Write-Host "      Iniciando directamente..."
        Start-Process "$NGINX_DIR\nginx.exe" -WorkingDirectory $NGINX_DIR -WindowStyle Hidden
    }

    $script:RESUMEN_INSTALACIONES += "Nginx   | SSL:$SSL | HTTP:$puerto_http  HTTPS:$puerto_https"
    Write-Host "OK Nginx instalado. Accede en http://127.0.0.1:$puerto_http"
}

# -------------------------------------------------------------
# TOMCAT PARA WINDOWS
# -------------------------------------------------------------
function Instalar-Tomcat {
    param($Archivo, $WebFTP, $SSL)

    Write-Host ""
    Write-Host "-- Configuracion de puertos para Tomcat ---------"
    $puertos = Pedir-Puerto "Tomcat" 8080 8443
    $puerto_http  = $puertos[0]
    $puerto_https = $puertos[1]

    # Verificar Java
    $java = Get-Command java -ErrorAction SilentlyContinue
    if (-not $java) {
        Write-Host "Java no encontrado. Descargando OpenJDK 17..."
        $wc = New-Object System.Net.WebClient
        $jdk_url = "https://aka.ms/download-jdk/microsoft-jdk-17-windows-x64.msi"
        $wc.DownloadFile($jdk_url, "$env:TEMP\jdk17.msi")
        Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\jdk17.msi`" /quiet /norestart" -Wait
        $env:Path += ";C:\Program Files\Microsoft\jdk-17\bin"
    }

    if ($WebFTP -eq "FTP") {
        if (-not (Descargar-Y-Validar "Tomcat" $Archivo)) { return }
        if (-not (Instalar-Paquete-Local $Archivo $TOMCAT_DIR)) { return }
    } else {
        Write-Host "Descargando Tomcat 10 desde tomcat.apache.org..."
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile(
            "https://dlcdn.apache.org/tomcat/tomcat-10/v10.1.30/bin/apache-tomcat-10.1.30-windows-x64.zip",
            "$env:TEMP\tomcat.zip"
        )
        New-Item -ItemType Directory -Force -Path $TOMCAT_DIR | Out-Null
        Expand-Archive "$env:TEMP\tomcat.zip" -DestinationPath $TOMCAT_DIR -Force
        $sub = Get-ChildItem $TOMCAT_DIR -Directory | Select-Object -First 1
        if ($sub) {
            Get-ChildItem "$($sub.FullName)\*" | Move-Item -Destination $TOMCAT_DIR -Force -ErrorAction SilentlyContinue
            Remove-Item $sub.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $docroot = "$TOMCAT_DIR\webapps\ROOT"
    $puerto_display = if ($SSL -eq "S") { $puerto_https } else { $puerto_http }
    Crear-Index "Tomcat" $puerto_display $docroot

    if ($SSL -eq "S") {
        $cert_dir = Generar-SSL "tomcat"
        $server_xml = @"
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$puerto_http" protocol="HTTP/1.1"
               connectionTimeout="20000" redirectPort="$puerto_https"/>
    <Connector port="$puerto_https"
               protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true">
      <SSLHostConfig>
        <Certificate certificateKeystoreFile="$cert_dir\server.pfx"
                     type="RSA"
                     certificateKeystorePassword="reprobados"/>
      </SSLHostConfig>
    </Connector>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>
"@
        # web.xml con HSTS
        $web_xml_dir = "$docroot\WEB-INF"
        New-Item -ItemType Directory -Force -Path $web_xml_dir | Out-Null
        $web_xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee" version="5.0">
  <filter>
    <filter-name>httpHeaderSecurity</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <init-param><param-name>hstsEnabled</param-name><param-value>true</param-value></init-param>
    <init-param><param-name>hstsMaxAgeSeconds</param-name><param-value>31536000</param-value></init-param>
    <init-param><param-name>hstsIncludeSubDomains</param-name><param-value>true</param-value></init-param>
  </filter>
  <filter-mapping>
    <filter-name>httpHeaderSecurity</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>Forzar HTTPS</web-resource-name>
      <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
      <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
  </security-constraint>
</web-app>
"@
        Set-Content "$web_xml_dir\web.xml" $web_xml
        Abrir-Puerto-Firewall $puerto_https "Tomcat-HTTPS"
        $script:SERVICIOS_VERIFICAR += "Tomcat-SSL|Tomcat10|${puerto_https}|https"
    } else {
        $server_xml = @"
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$puerto_http" protocol="HTTP/1.1" connectionTimeout="20000"/>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>
"@
    }

    Set-Content "$TOMCAT_DIR\conf\server.xml" $server_xml

    Abrir-Puerto-Firewall $puerto_http "Tomcat-HTTP"
    $script:SERVICIOS_VERIFICAR += "Tomcat|Tomcat10|${puerto_http}|http"

    # Instalar Tomcat como servicio Windows
    $service_bat = "$TOMCAT_DIR\bin\service.bat"
    if (Test-Path $service_bat) {
        $env:CATALINA_HOME = $TOMCAT_DIR
        & cmd /c "`"$service_bat`" install Tomcat10" 2>$null
        Start-Service "Tomcat10" -ErrorAction SilentlyContinue
        Set-Service  "Tomcat10" -StartupType Automatic -ErrorAction SilentlyContinue
        Write-Host "Esperando que Tomcat levante (8s)..."
        Start-Sleep -Seconds 8
    } else {
        Write-Host "ADVERTENCIA: service.bat no encontrado."
    }

    $script:RESUMEN_INSTALACIONES += "Tomcat  | SSL:$SSL | HTTP:$puerto_http  HTTPS:$puerto_https"
    Write-Host "OK Tomcat instalado. Accede en http://127.0.0.1:$puerto_http"
}

# -------------------------------------------------------------
# FILEZILLA SERVER (FTP para Windows, reemplaza vsftpd)
# -------------------------------------------------------------
function Instalar-FileZilla {
    param($Archivo, $WebFTP, $SSL)

    if ($WebFTP -eq "FTP") {
        if (-not (Descargar-Y-Validar "FileZilla" $Archivo)) { return }
        if (-not (Instalar-Paquete-Local $Archivo $FZ_DIR)) { return }
    } else {
        Write-Host "Descargando FileZilla Server..."
        $wc  = New-Object System.Net.WebClient
        $url = "https://dl2.cdn.filezilla-project.org/server/FileZilla_Server_1.8.2_win64-setup.exe"
        $wc.DownloadFile($url, "$env:TEMP\fzserver.exe")
        # Instalacion silenciosa
        Start-Process "$env:TEMP\fzserver.exe" -ArgumentList "/S" -Wait
    }

    if ($SSL -eq "S") {
        Generar-SSL "filezilla" | Out-Null
        Write-Host "NOTA: Configura el certificado en FileZilla Server Admin:"
        Write-Host "      $SSL_DIR\filezilla\server.pfx  (pass: reprobados)"
        Abrir-Puerto-Firewall 990 "FileZilla-FTPS"
        $script:SERVICIOS_VERIFICAR += "FileZilla-FTPS|FileZilla Server|990|ftps"
    } else {
        Abrir-Puerto-Firewall 21 "FileZilla-FTP"
        $script:SERVICIOS_VERIFICAR += "FileZilla|FileZilla Server|21|ftp"
    }

    Abrir-Puerto-Firewall 40000 "FileZilla-PASV-start"
    $script:RESUMEN_INSTALACIONES += "FileZilla | SSL:$SSL | FTP:21  FTPS:990"
    Write-Host "OK FileZilla Server instalado."
    Write-Host "   Configura usuarios y puertos en FileZilla Server Admin (localhost:14148)"
}

# -------------------------------------------------------------
# VERIFICACION DE SERVICIOS
# -------------------------------------------------------------
function Verificar-HTTP {
    param($Nombre, $Servicio, $Puerto, $Proto)

    $estado = "INACTIVO"
    $svc = Get-Service $Servicio -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { $estado = "ACTIVO" }

    $resp = "N/A"
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $r = Invoke-WebRequest "${Proto}://127.0.0.1:${Puerto}" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $resp = $r.StatusCode
    } catch {
        if ($_.Exception.Response) { $resp = [int]$_.Exception.Response.StatusCode }
    }

    Write-Host "  [$Nombre] Proceso: $estado | Puerto $Puerto ($Proto): HTTP $resp"

    if ($Proto -eq "https") {
        try {
            $headers = Invoke-WebRequest "${Proto}://127.0.0.1:${Puerto}" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            $hsts = $headers.Headers["Strict-Transport-Security"]
            if ($hsts) { Write-Host "  [$Nombre] HSTS: OK ($hsts)" }
            else        { Write-Host "  [$Nombre] HSTS: no encontrado" }
        } catch {}
    }
}

function Verificar-FTP {
    param($Nombre, $Puerto)
    $estado = "INACTIVO"
    $svc = Get-Service "FileZilla Server" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { $estado = "ACTIVO" }

    $conexion = "CERRADO"
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect("127.0.0.1", $Puerto)
        if ($tcp.Connected) { $conexion = "ABIERTO" }
        $tcp.Close()
    } catch {}

    Write-Host "  [$Nombre] Proceso: $estado | Puerto $Puerto (TCP): $conexion"
}

# -------------------------------------------------------------
# RESUMEN AUTOMATIZADO
# -------------------------------------------------------------
function Mostrar-Resumen {
    Write-Host ""
    Write-Host "=========================================================="
    Write-Host "         RESUMEN AUTOMATIZADO DE SERVICIOS               "
    Write-Host "=========================================================="

    if ($script:RESUMEN_INSTALACIONES.Count -eq 0) {
        Write-Host "  No se ha instalado ningun servicio en esta sesion."
    } else {
        Write-Host ""
        Write-Host "-- Servicios instalados en esta sesion ------------------"
        foreach ($r in $script:RESUMEN_INSTALACIONES) {
            Write-Host "  -> $r"
        }
    }

    Write-Host ""
    Write-Host "-- Verificacion activa de cada servicio -----------------"
    if ($script:SERVICIOS_VERIFICAR.Count -eq 0) {
        Write-Host "  (sin servicios registrados aun)"
    } else {
        foreach ($entrada in $script:SERVICIOS_VERIFICAR) {
            $partes = $entrada -split "\|"
            $nombre=$partes[0]; $unit=$partes[1]; $puerto=$partes[2]; $proto=$partes[3]
            if ($proto -in "http","https") { Verificar-HTTP $nombre $unit $puerto $proto }
            else { Verificar-FTP $nombre $puerto }
        }
    }

    Write-Host ""
    Write-Host "-- Puertos activos en el sistema ------------------------"
    netstat -an | Select-String "LISTENING" | ForEach-Object {
        $cols = $_ -split "\s+"
        Write-Host "  $($cols[2])"
    } | Sort-Object -Unique

    Write-Host "=========================================================="
}

# -------------------------------------------------------------
# PREPARAR REPOSITORIO FTP LOCAL (para Windows)
# -------------------------------------------------------------
function Preparar-Repositorio-FTP {
    $base = "C:\inetpub\ftproot\repositorio\Windows"
    Write-Host ""
    Write-Host "=========================================================="
    Write-Host "         PREPARANDO REPOSITORIO FTP LOCAL (WINDOWS)      "
    Write-Host "=========================================================="
    Write-Host "Ruta base: $base"

    foreach ($svc in @("Apache","Nginx","Tomcat","FileZilla")) {
        New-Item -ItemType Directory -Force -Path "$base\$svc" | Out-Null
    }

    Write-Host ""
    Write-Host "Descarga los instaladores manualmente y colocalos en:"
    Write-Host "  $base\Apache\   -> httpd-x.x.x-win64.zip"
    Write-Host "  $base\Nginx\    -> nginx-x.x.x.zip"
    Write-Host "  $base\Tomcat\   -> apache-tomcat-x.x.x-windows-x64.zip"
    Write-Host "  $base\FileZilla\ -> FileZilla_Server_x.x.x_win64-setup.exe"
    Write-Host ""
    Write-Host "Luego genera los SHA256 con:"
    Write-Host '  Get-FileHash .\archivo.zip -Algorithm SHA256 | Select-Object -ExpandProperty Hash > archivo.zip.sha256'
    Write-Host "=========================================================="
}

# -------------------------------------------------------------
# PUNTO DE ENTRADA
# -------------------------------------------------------------
Main
