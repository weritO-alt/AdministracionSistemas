# ==============================================================================
# MODULO HTTP/FTP COMBINADO - WINDOWS (P07)
# ==============================================================================

Import-Module WebAdministration -ErrorAction SilentlyContinue

$PUERTOS_BLOQUEADOS = @(1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,
    87,95,101,102,103,104,109,110,111,113,115,117,119,123,135,139,142,143,179,389,
    465,512,513,514,515,526,530,531,532,540,548,554,556,563,587,601,636,993,995,
    2049,3659,4045,6000,6665,6666,6667,6668,6669,6697)

# ================================================================
# LIMPIEZA Y PAGINA
# ================================================================

function Limpiar-Entorno {
    param($Puerto)
    Write-Host "[*] Limpiando servicios en puerto $Puerto..." -ForegroundColor Gray
    Stop-Service nginx, Apache, Apache2.4, W3SVC, ftpsvc -Force -ErrorAction SilentlyContinue
    taskkill /F /IM nginx.exe /T 2>$null
    taskkill /F /IM httpd.exe /T 2>$null
    $con = Get-NetTCPConnection -LocalPort $Puerto -State Listen -ErrorAction SilentlyContinue
    if ($con) { $con.OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue } }
    Start-Sleep -Seconds 2
}

function Crear-Pagina {
    param($servicio, $puerto)
    $paths = @{
        "nginx"  = "C:\tools\nginx-1.29.6\html\index.html"
        "apache" = "C:\Users\Administrator\AppData\Roaming\Apache24\htdocs\index.html"
        "iis"    = "C:\inetpub\wwwroot\index.html"
    }
    $path = $paths[$servicio]
    if (!$path) { return }
    $dir = Split-Path $path
    if (!(Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
    $html  = "<html>"
    $html += "<head><title>$($servicio.ToUpper()) - Puerto $puerto</title></head>"
    $html += "<body>"
    $html += "<h1>$($servicio.ToUpper()) Activo</h1>"
    $html += "<p>Servicio: $($servicio.ToUpper())</p>"
    $html += "<p>Puerto: $puerto</p>"

    $html += "</body>"
    $html += "</html>"
    Set-Content $path $html -Encoding ASCII
}

# ================================================================
# CERTIFICADO SSL
# ================================================================

function Generar-Certificado-SSL {
    $dir = "C:\ssl\reprobados"
    $crt = "$dir\reprobados.crt"
    $key = "$dir\reprobados.key"

    if (!(Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }

    $crtOk = (Test-Path $crt) -and ((Get-Content $crt -First 1) -like "-----BEGIN*")
    $keyOk = (Test-Path $key) -and ((Get-Content $key -First 1) -like "-----BEGIN*")

    if ($crtOk -and $keyOk) {
        Write-Host "[*] Reutilizando certificado existente." -ForegroundColor Yellow
        return @{ CRT = $crt; KEY = $key; OK = $true }
    }

    $opensslPath = $null
    foreach ($c in @("C:\Program Files\Git\usr\bin\openssl.exe","C:\Program Files (x86)\Git\usr\bin\openssl.exe","C:\ProgramData\chocolatey\bin\openssl.exe")) {
        if (Test-Path $c) { $opensslPath = $c; break }
    }
    if (!$opensslPath) {
        $cmd = Get-Command openssl -ErrorAction SilentlyContinue
        if ($cmd) { $opensslPath = $cmd.Source }
    }

    if ($opensslPath) {
        Write-Host "[*] Generando certificado SSL con OpenSSL..." -ForegroundColor Cyan
        & $opensslPath genrsa -out $key 2048 2>$null
        & $opensslPath req -new -x509 -key $key -out $crt -days 365 -subj "/C=MX/ST=Sinaloa/L=LosMochis/O=Reprobados/CN=www.reprobados.com" 2>$null
        Write-Host "[OK] CRT: $(Get-Content $crt -First 1)" -ForegroundColor Green
        Write-Host "[OK] KEY: $(Get-Content $key -First 1)" -ForegroundColor Green
        return @{ CRT = $crt; KEY = $key; OK = $true }
    } else {
        Write-Host "[!] OpenSSL no encontrado. Solo IIS usara SSL." -ForegroundColor Yellow
        return @{ CRT = $crt; KEY = $key; OK = $false }
    }
}

function Obtener-CertObj {
    $certObj = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*reprobados*" } | Select-Object -First 1
    if (!$certObj) {
        $certObj = New-SelfSignedCertificate -DnsName "www.reprobados.com" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddDays(365) -KeyExportPolicy Exportable
    }
    return $certObj
}

# ================================================================
# DESPLIEGUE POR SERVICIO
# ================================================================

function Aplicar-Despliegue {
    param($Servicio)

    if (-not ($global:PUERTO_ACTUAL -match '^\d+$')) {
        $global:PUERTO_ACTUAL = Read-Host "Puerto a usar"
    }
    $P    = [int]$global:PUERTO_ACTUAL
    $cert = Generar-Certificado-SSL

    # ---- NUEVO: Pregunta de SSL ----
    $respSSL  = Read-Host "Desea activar SSL en este servicio? [S/N]"
    $usarSSL  = ($respSSL -match '^[Ss]$') -and $cert.OK
    $protocolo = if ($usarSSL) { "https" } else { "http" }
    Write-Host "[*] SSL: $(if ($usarSSL) { 'ACTIVADO' } else { 'DESACTIVADO' })" -ForegroundColor $(if ($usarSSL) { 'Green' } else { 'Yellow' })

    Limpiar-Entorno $P

    switch ($Servicio) {

        "nginx" {
            $nginxExeItem = Get-ChildItem "C:\tools\nginx" -Recurse -Filter "nginx.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (!$nginxExeItem) { Write-Host "[!] nginx.exe no encontrado en C:\tools\nginx" -ForegroundColor Red; Pause; return }
            $nginxDir = $nginxExeItem.DirectoryName
            $conf     = "$nginxDir\conf\nginx.conf"
            $certAbs  = "C:/ssl/reprobados/reprobados.crt"
            $keyAbs   = "C:/ssl/reprobados/reprobados.key"

            if ($usarSSL) {
                # ---- NUEVO: Bloque HTTP en puerto 80 que redirige a HTTPS ----
                $cfg = @"
worker_processes  1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;

    # Redireccion HTTP -> HTTPS (HSTS basico)
    server {
        listen       80;
        server_name  www.reprobados.com;
        return 301   https://`$host:$P`$request_uri;
    }

    server {
        listen       $P ssl;
        server_name  www.reprobados.com;
        ssl_certificate      $certAbs;
        ssl_certificate_key  $keyAbs;
        add_header Strict-Transport-Security "max-age=31536000" always;
        location / { root html; index index.html; }
    }
}
"@
            } else {
                $cfg = @"
worker_processes  1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    server {
        listen       $P;
        server_name  www.reprobados.com;
        location / { root html; index index.html; }
    }
}
"@
            }
            Set-Content $conf $cfg -Encoding ASCII
            Crear-Pagina "nginx" $P
            Start-Process "$nginxDir\nginx.exe" -WorkingDirectory $nginxDir -WindowStyle Hidden
            Start-Sleep -Seconds 3
        }

        "apache" {
            $rutaApache = $null
            $svcWmi = Get-CimInstance Win32_Service | Where-Object { $_.Name -like "Apache*" } | Select-Object -First 1
            if ($svcWmi) {
                if ($svcWmi.PathName -match '"([^"]+bin[^"]+httpd\.exe)"') {
                    $rutaApache = Split-Path (Split-Path $matches[1] -Parent) -Parent
                } elseif ($svcWmi.PathName -match '([A-Za-z]:[^ ]+httpd\.exe)') {
                    $rutaApache = Split-Path (Split-Path $matches[1] -Parent) -Parent
                }
            }
            if (!$rutaApache) {
                foreach ($c in @("C:\Apache24","$env:APPDATA\Apache24")) {
                    if (Test-Path "$c\bin\httpd.exe") { $rutaApache = $c; break }
                }
            }
            if (!$rutaApache) { Write-Host "[!] Apache no encontrado." -ForegroundColor Red; Pause; return }
            Write-Host "[*] Apache en: $rutaApache" -ForegroundColor Cyan

            $conf    = "$rutaApache\conf\httpd.conf"
            $webRoot = "$rutaApache\htdocs"
            $certDir = "C:/ssl/reprobados"

            $lineas = Get-Content $conf
            for ($i = 200; $i -lt $lineas.Count; $i++) {
                if ($lineas[$i] -match '^<VirtualHost') { $lineas = $lineas[0..($i-1)]; break }
            }

            $primeraListen = $true
            $tieneListenLigne = $false
            $lineas = $lineas | ForEach-Object {
                if ($_ -match '^Listen ') {
                    if ($primeraListen) { $primeraListen = $false; $tieneListenLigne = $true; "Listen $P" }
                }
                elseif ($_ -match '^#Listen ')              { $tieneListenLigne = $true; "Listen $P" }
                elseif ($_ -match '^#?ServerName ')          { "ServerName www.reprobados.com:$P" }
                elseif ($_ -match '^#LoadModule ssl_module') { "LoadModule ssl_module modules/mod_ssl.so" }
                elseif ($_ -match '^#LoadModule socache_shmcb_module') { "LoadModule socache_shmcb_module modules/mod_socache_shmcb.so" }
                else { $_ }
            }
            if (!$tieneListenLigne) { $lineas = @("Listen $P") + $lineas }

            $webDir = $webRoot -replace '\\','/'

            if ($usarSSL) {
                # ---- NUEVO: VirtualHost HTTP en 80 que redirige a HTTPS ----
                $vhost = @"

# Escuchar tambien en 80 para la redireccion
Listen 80

<VirtualHost *:80>
    ServerName www.reprobados.com
    Redirect permanent / https://www.reprobados.com:$P/
    Header always set Strict-Transport-Security "max-age=31536000"
</VirtualHost>

<VirtualHost *:$P>
    ServerName www.reprobados.com
    DocumentRoot "$webDir"
    SSLEngine on
    SSLCertificateFile    "$certDir/reprobados.crt"
    SSLCertificateKeyFile "$certDir/reprobados.key"
    Header always set Strict-Transport-Security "max-age=31536000"
    <Directory "$webDir">
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
"@
            } else {
                $vhost = @"

<VirtualHost *:$P>
    ServerName www.reprobados.com
    DocumentRoot "$webDir"
    <Directory "$webDir">
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
"@
            }
            $lineas += ($vhost -split "`n")
            Set-Content $conf $lineas -Encoding ASCII

            $test = & "$rutaApache\bin\httpd.exe" -t 2>&1
            $ok   = $test | Where-Object { $_ -like "*Syntax OK*" }
            Write-Host "[*] Sintaxis: $(if ($ok) { 'OK' } else { 'ERROR' })" -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
            if (!$ok) { $test | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }; Pause; return }

            Crear-Pagina "apache" $P
            Get-Process httpd -ErrorAction SilentlyContinue | Stop-Process -Force
            Start-Sleep -Seconds 1

            $svc = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($svc) {
                try { Restart-Service $svc.Name -Force -ErrorAction Stop }
                catch { Start-Process "$rutaApache\bin\httpd.exe" -WorkingDirectory "$rutaApache" -WindowStyle Hidden }
            } else {
                Start-Process "$rutaApache\bin\httpd.exe" -WorkingDirectory "$rutaApache" -WindowStyle Hidden
            }
            Start-Sleep -Seconds 4
            if (!(Get-NetTCPConnection -LocalPort $P -State Listen -ErrorAction SilentlyContinue)) {
                & "$rutaApache\bin\httpd.exe" -k start 2>$null
                Start-Sleep -Seconds 3
            }
        }

        "iis" {
            $certObj = Obtener-CertObj
            $webRoot = "C:\inetpub\wwwroot"
            if (!(Test-Path $webRoot)) { New-Item $webRoot -ItemType Directory -Force | Out-Null }
            Crear-Pagina "iis" $P
            try {
                Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
                New-Website -Name "Default Web Site" -Port $P -PhysicalPath $webRoot -Force | Out-Null

                if ($usarSSL) {
                    # Quitar binding HTTP y dejar solo HTTPS
                    Get-WebBinding -Name "Default Web Site" -Protocol "http" | Remove-WebBinding -ErrorAction SilentlyContinue
                    New-WebBinding -Name "Default Web Site" -Protocol "https" -Port $P -IPAddress "*"
                    $sslPath = "IIS:\SslBindings\*!$P"
                    if (!(Test-Path $sslPath)) {
                        Get-Item "Cert:\LocalMachine\My\$($certObj.Thumbprint)" | New-Item -Path $sslPath -Force | Out-Null
                    }

                    # ---- NUEVO: Agregar binding HTTP en 80 con redireccion a HTTPS ----
                    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port 80 -IPAddress "*" -ErrorAction SilentlyContinue

                    # Activar HTTP Redirect de IIS hacia HTTPS
                    Set-WebConfigurationProperty -Filter "system.webServer/httpRedirect" `
                        -Name "enabled" -Value $true `
                        -PSPath "IIS:\Sites\Default Web Site" -ErrorAction SilentlyContinue
                    Set-WebConfigurationProperty -Filter "system.webServer/httpRedirect" `
                        -Name "destination" -Value "https://www.reprobados.com:$P" `
                        -PSPath "IIS:\Sites\Default Web Site" -ErrorAction SilentlyContinue
                    Set-WebConfigurationProperty -Filter "system.webServer/httpRedirect" `
                        -Name "httpResponseStatus" -Value "Permanent" `
                        -PSPath "IIS:\Sites\Default Web Site" -ErrorAction SilentlyContinue

                    Write-Host "[OK] Redireccion HTTP->HTTPS configurada en IIS." -ForegroundColor Green
                } else {
                    New-WebBinding -Name "Default Web Site" -Protocol "http" -Port $P -IPAddress "*" -ErrorAction SilentlyContinue
                }
            } catch { Write-Host "[!] $($_.Exception.Message)" -ForegroundColor Red }
            Start-Service W3SVC -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }

    Start-Sleep -Seconds 2
    if (Get-NetTCPConnection -LocalPort $P -State Listen -ErrorAction SilentlyContinue) {
        Write-Host "[OK] $Servicio ONLINE en puerto $P" -ForegroundColor Green
        Write-Host "     Acceso: ${protocolo}://192.168.1.235:$P" -ForegroundColor Cyan
    } else {
        Write-Host "[!] $Servicio no levanto en puerto $P" -ForegroundColor Red
    }
    Pause
}

# ================================================================
# FTP PRIVADO
# ================================================================

function Listar-Archivos-FTP {
    param($url, $usuario, $clave)
    try {
        $req = [System.Net.FtpWebRequest]::Create($url)
        $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
        $req.Credentials = New-Object System.Net.NetworkCredential($usuario, $clave)
        $req.UsePassive = $true; $req.UseBinary = $true; $req.KeepAlive = $false
        $resp   = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $lista  = $reader.ReadToEnd(); $reader.Close(); $resp.Close()

        $archivos = @()
        foreach ($linea in ($lista -split "`n")) {
            $l = $linea.Trim().TrimEnd("`r")
            if ($l -eq "") { continue }
            $tokens = ($l -split " +") | Where-Object { $_ -ne "" }
            if ($tokens.Count -ge 4) {
                $nombre = $tokens[-1]
                if ($nombre -notlike "*.sha256" -and $nombre -ne "") {
                    $archivos += $nombre
                }
            }
        }
        return $archivos
    } catch {
        Write-Host "[!] Error FTP: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Descargar-FTP {
    param($url, $destino, $usuario, $clave)
    try {
        $req = [System.Net.FtpWebRequest]::Create($url)
        $req.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        $req.Credentials = New-Object System.Net.NetworkCredential($usuario, $clave)
        $req.UsePassive = $true; $req.UseBinary = $true; $req.KeepAlive = $false
        $resp = $req.GetResponse()
        $fs   = [System.IO.File]::Create($destino)
        $resp.GetResponseStream().CopyTo($fs); $fs.Close(); $resp.Close()
        return $true
    } catch {
        Write-Host "[!] Error descargando: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Instalar-Servicio {
    param($Servicio)
    $ServicioFTP = switch ($Servicio.ToLower()) {
        "nginx"  { "Nginx" }
        "apache" { "Apache" }
        "iis"    { "IIS" }
        default  { $Servicio }
    }
    $paquete = switch ($Servicio.ToLower()) {
        "nginx"  { "nginx" }
        "apache" { "apache-httpd" }
        "iis"    { "iis" }
    }

    Write-Host ""; Write-Host "[I] --- Instalando: $Servicio ---" -ForegroundColor Blue
    Write-Host "1) Chocolatey (Oficial) | 2) FTP ($global:FTP_IP)"
    $origen = Read-Host "Elija origen"

    if ($origen -eq "1") {
        if ($Servicio -eq "iis") {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools
            Install-WindowsFeature -Name Web-Http-Redirect -ErrorAction SilentlyContinue
            Write-Host "[OK] IIS instalado." -ForegroundColor Green
            Pause
            $dep = Read-Host "Desplegar IIS en puerto $global:PUERTO_ACTUAL? [S/N]"
            if ($dep -match '^[Ss]$') { Aplicar-Despliegue "iis" }
            return
        }
        $chocoExe = "C:\ProgramData\chocolatey\bin\choco.exe"
        Limpiar-Entorno 80
        Write-Host "[*] Consultando versiones para $paquete..." -ForegroundColor Cyan
        $raw  = & $chocoExe search $paquete --exact --limit-output 2>$null
        $vers = @($raw | Where-Object { $_ -match '^\S+\|\d' })
        if ($vers.Count -eq 0) {
            Write-Host "[...] Instalando..." -ForegroundColor Gray
            & $chocoExe install $paquete -y | Out-Null
        } else {
            Write-Host "Versiones:"
            for ($i=0; $i -lt $vers.Count; $i++) { $p=$vers[$i].Split('|'); Write-Host "$($i+1)) $($p[0]) v$($p[1])" }
            $sel = Read-Host "Elija (ENTER=ultima)"
            Write-Host "[...] Instalando..." -ForegroundColor Gray
            if ([string]::IsNullOrWhiteSpace($sel)) {
                & $chocoExe install $paquete -y | Out-Null
            } else {
                $si = 0
                if ([int]::TryParse($sel,[ref]$si) -and $si -ge 1 -and $si -le $vers.Count) {
                    $v = $vers[$si-1].Split('|')[1].Trim()
                    & $chocoExe install $paquete --version $v -y | Out-Null
                } else { & $chocoExe install $paquete -y | Out-Null }
            }
        }
        Write-Host "[OK] Instalacion completada." -ForegroundColor Green
    } else {
        $ftpDir  = "$global:FTP_BASE/$ServicioFTP"
        Write-Host "[*] Listando $ftpDir ..." -ForegroundColor Cyan
        $archivos = Listar-Archivos-FTP $ftpDir $global:FTP_USER $global:FTP_PASS
        if ($archivos.Count -eq 0) { Pause; return }
        for ($i=0; $i -lt $archivos.Count; $i++) { Write-Host "$($i+1)) $($archivos[$i])" }
        $idx = 0; $sel = Read-Host "Seleccione"
        if (![int]::TryParse($sel,[ref]$idx) -or $idx -lt 1 -or $idx -gt $archivos.Count) { Write-Host "[!] Invalido."; Pause; return }
        $archivo   = $archivos[$idx-1]
        $destLocal = Join-Path $env:TEMP $archivo
        Write-Host "[*] Descargando $archivo..." -ForegroundColor Yellow
        if (!(Descargar-FTP "$ftpDir/$archivo" $destLocal $global:FTP_USER $global:FTP_PASS)) { Pause; return }
        $ok2 = Descargar-FTP "$ftpDir/$archivo.sha256" "$destLocal.sha256" $global:FTP_USER $global:FTP_PASS
        if ($ok2 -and (Test-Path "$destLocal.sha256")) {
            $h1 = (Get-FileHash $destLocal -Algorithm SHA256).Hash.ToUpper()
            $h2 = (Get-Content "$destLocal.sha256").Trim().Split()[0].ToUpper()
            if ($h1 -ne $h2) { Write-Host "[!] Hash invalido." -ForegroundColor Red; Pause; return }
            Write-Host "[OK] Hash verificado." -ForegroundColor Green
        }
        if ($archivo -like "*.zip") {
            $dest = "C:\tools\$Servicio"
            if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
            Expand-Archive -Path $destLocal -DestinationPath $dest -Force
            Write-Host "[OK] Extraido en $dest" -ForegroundColor Green
        } elseif ($archivo -like "*.msi") {
            Start-Process msiexec.exe -ArgumentList "/i `"$destLocal`" /quiet" -Wait
        }
    }

    $dep = Read-Host "Desplegar ahora en puerto $global:PUERTO_ACTUAL? [S/N]"
    if ($dep -match '^[Ss]$') { Aplicar-Despliegue $Servicio }
}

# ================================================================
# FTP SEGURO
# ================================================================

function Configurar-FTP-Seguro {
    $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"

    $sitioFTP = & $appcmd list site 2>$null |
        ForEach-Object { if ($_ -match 'SITE object "([^"]+)"') { $matches[1] } } |
        Where-Object { $_ -ne "" } | Select-Object -First 1

    if (!$sitioFTP) {
        if (!(Test-Path "C:\FTP_Publico")) { New-Item "C:\FTP_Publico" -ItemType Directory -Force | Out-Null }
        & $appcmd add site /name:"ServidorFTP" /bindings:"ftp/*:21:" /physicalPath:"C:\FTP_Publico" 2>$null
        $sitioFTP = "ServidorFTP"
    }

    Write-Host "[*] Sitio FTP detectado: $sitioFTP" -ForegroundColor Cyan
    $certObj = Obtener-CertObj
    & $appcmd set site "$sitioFTP" "-ftpServer.security.ssl.controlChannelPolicy:SslAllow" 2>$null
    & $appcmd set site "$sitioFTP" "-ftpServer.security.ssl.dataChannelPolicy:SslAllow" 2>$null
    & $appcmd set site "$sitioFTP" "-ftpServer.security.ssl.serverCertHash:$($certObj.Thumbprint)" 2>$null
    & $appcmd set config "$sitioFTP" /section:system.ftpServer/security/authentication/anonymousAuthentication /enabled:true /commit:apphost 2>$null
    & $appcmd set config "$sitioFTP" /section:system.ftpServer/security/authentication/basicAuthentication /enabled:true /commit:apphost 2>$null

    Set-Service ftpsvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service ftpsvc -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & $appcmd start site "$sitioFTP" 2>$null
    Start-Sleep -Seconds 2

    if (Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue) {
        Write-Host "[OK] FTP ONLINE en puerto 21 - Sitio: $sitioFTP" -ForegroundColor Green
    } else {
        Restart-Service ftpsvc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        & $appcmd start site "$sitioFTP" 2>$null
        Start-Sleep -Seconds 2
        if (Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue) {
            Write-Host "[OK] FTP ONLINE." -ForegroundColor Green
        } else {
            Write-Host "[!] FTP no levanto. Ejecuta: net start ftpsvc" -ForegroundColor Red
        }
    }
    Pause
}

# ================================================================
# VALIDAR PUERTO
# ================================================================

function Validar-Puerto-Seguro {
    while ($true) {
        $nuevo = Read-Host "Ingrese el puerto (recomendado: 8080, 8443, 9090)"
        if (-not ($nuevo -match '^\d+$') -or [int]$nuevo -lt 1 -or [int]$nuevo -gt 65535) {
            Write-Host "[!] Puerto invalido." -ForegroundColor Red; continue
        }
        if ([int]$nuevo -in $PUERTOS_BLOQUEADOS) {
            Write-Host "[!] Puerto $nuevo bloqueado por navegadores." -ForegroundColor Yellow
            $c = Read-Host "    Usar de todas formas? [S/N]"
            if ($c -notmatch '^[Ss]$') { continue }
        }
        $global:PUERTO_ACTUAL = $nuevo
        Write-Host "[OK] Puerto $nuevo asignado." -ForegroundColor Green
        return
    }
}

# ================================================================
# NUEVO: RESUMEN AUTOMATICO DE SERVICIOS
# ================================================================

function Mostrar-Resumen {
    $p = if ($global:PUERTO_ACTUAL -and $global:PUERTO_ACTUAL -ne "N/A") { [int]$global:PUERTO_ACTUAL } else { 0 }

    # Definicion de los servicios a verificar
    $servicios = @(
        @{ Nombre = "Nginx (HTTP)";   Puerto = $p;   Protocolo = "http"  }
        @{ Nombre = "Nginx (HTTPS)";  Puerto = $p;   Protocolo = "https" }
        @{ Nombre = "Apache (HTTP)";  Puerto = $p;   Protocolo = "http"  }
        @{ Nombre = "Apache (HTTPS)"; Puerto = $p;   Protocolo = "https" }
        @{ Nombre = "IIS (HTTP)";     Puerto = 80;   Protocolo = "http"  }
        @{ Nombre = "IIS (HTTPS)";    Puerto = $p;   Protocolo = "https" }
        @{ Nombre = "IIS-FTP";        Puerto = 21;   Protocolo = "ftp"   }
        @{ Nombre = "Redireccion 80"; Puerto = 80;   Protocolo = "http"  }
    )

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   RESUMEN DE INFRAESTRUCTURA - $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ("{0,-25} {1,-8} {2,-10} {3}" -f "Servicio", "Puerto", "Estado", "Detalle") -ForegroundColor White
    Write-Host ("-" * 62) -ForegroundColor Gray

    $activos = 0
    $total   = 0

    foreach ($svc in $servicios) {
        if ($svc.Puerto -eq 0) {
            Write-Host ("{0,-25} {1,-8} {2,-10} {3}" -f $svc.Nombre, "N/A", "SKIP", "Puerto no configurado") -ForegroundColor DarkGray
            continue
        }

        $total++
        $escuchando = Get-NetTCPConnection -LocalPort $svc.Puerto -State Listen -ErrorAction SilentlyContinue

        if ($escuchando) {
            $activos++

            # Verificacion SSL para HTTPS
            $sslOk = $false
            $sslDetalle = ""
            if ($svc.Protocolo -eq "https") {
                try {
                    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                    $req = [System.Net.HttpWebRequest]::Create("https://localhost:$($svc.Puerto)")
                    $req.Timeout = 4000
                    $resp = $req.GetResponse()
                    $sslOk = $true
                    $sslDetalle = "SSL OK"
                    $resp.Close()
                } catch {
                    $sslDetalle = "SSL ERROR: $($_.Exception.Message -replace '.{0,50}$','')"
                }
                [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }

            # Verificacion certificado reprobados.com
            $certInfo = ""
            if ($svc.Protocolo -eq "https") {
                $certObj = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*reprobados*" } | Select-Object -First 1
                if ($certObj) {
                    $dias = ($certObj.NotAfter - (Get-Date)).Days
                    $certInfo = "Cert: reprobados.com (vence en $dias dias)"
                } else {
                    $certInfo = "Cert: NO ENCONTRADO"
                }
            }

            $detalle = if ($svc.Protocolo -eq "https") { "$sslDetalle | $certInfo" } else { "Escuchando" }
            $color   = if ($svc.Protocolo -eq "https" -and !$sslOk) { "Yellow" } else { "Green" }
            Write-Host ("{0,-25} {1,-8} {2,-10} {3}" -f $svc.Nombre, $svc.Puerto, "[ACTIVO]", $detalle) -ForegroundColor $color
        } else {
            Write-Host ("{0,-25} {1,-8} {2,-10} {3}" -f $svc.Nombre, $svc.Puerto, "[INACTIVO]", "No escucha en este puerto") -ForegroundColor Red
        }
    }

    Write-Host ("-" * 62) -ForegroundColor Gray
    Write-Host ("Servicios activos: $activos / $total") -ForegroundColor $(if ($activos -eq $total) { "Green" } else { "Yellow" })

    # Certificado SSL global
    Write-Host ""
    Write-Host "--- Certificado SSL en almacen Windows ---" -ForegroundColor Cyan
    $certObj = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*reprobados*" } | Select-Object -First 1
    if ($certObj) {
        Write-Host "  Subject  : $($certObj.Subject)" -ForegroundColor Green
        Write-Host "  Emitido  : $($certObj.NotBefore.ToString('dd/MM/yyyy'))" -ForegroundColor Green
        Write-Host "  Vence    : $($certObj.NotAfter.ToString('dd/MM/yyyy'))" -ForegroundColor Green
        Write-Host "  Thumbprint: $($certObj.Thumbprint)" -ForegroundColor Green
    } else {
        Write-Host "  [!] Certificado reprobados.com NO encontrado en el almacen." -ForegroundColor Red
    }

    # Archivos de certificado en disco
    Write-Host ""
    Write-Host "--- Archivos SSL en disco ---" -ForegroundColor Cyan
    foreach ($f in @("C:\ssl\reprobados\reprobados.crt","C:\ssl\reprobados\reprobados.key")) {
        if (Test-Path $f) {
            Write-Host "  [OK] $f" -ForegroundColor Green
        } else {
            Write-Host "  [!] NO existe: $f" -ForegroundColor Red
        }
    }

    Write-Host "============================================================" -ForegroundColor Cyan
    Pause
}

# ================================================================
# MENU PRINCIPAL
# ================================================================

function Asegurar-FTP-Activo {
    $ftpActivo = Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue
    if (!$ftpActivo) {
        Write-Host "[*] Arrancando servicio FTP..." -ForegroundColor Yellow
        Set-Service ftpsvc -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service ftpsvc -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
        & $appcmd list site 2>$null |
            ForEach-Object { if ($_ -match 'SITE object "([^"]+)"') { $matches[1] } } |
            Where-Object { $_ -ne "" } |
            ForEach-Object { & $appcmd start site "$_" 2>$null }
        Start-Sleep -Seconds 2
        if (Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue) {
            Write-Host "[OK] FTP activo en puerto 21." -ForegroundColor Green
        } else {
            Write-Host "[!] FTP no pudo arrancar." -ForegroundColor Red
        }
    }
}

function Menu-FTP-HTTP {
    $global:FTP_IP   = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1).IPAddress
    $global:FTP_USER = "anonymous"
    $global:FTP_PASS = ""
    $global:FTP_BASE = "ftp://127.0.0.1/http/Windows"

    Asegurar-FTP-Activo

    while ($true) {
        $p = if ($global:PUERTO_ACTUAL -and $global:PUERTO_ACTUAL -ne "N/A") { $global:PUERTO_ACTUAL } else { "N/A" }
        Write-Host ""
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host "      MODULO HTTP/FTP - IP: $global:FTP_IP" -ForegroundColor Cyan
        Write-Host "      PUERTO CONFIGURADO: $p" -ForegroundColor Yellow
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host " 1) Instalar + Desplegar Nginx"
        Write-Host " 2) Instalar + Desplegar Apache"
        Write-Host " 3) Instalar + Desplegar IIS"
        Write-Host " 4) Configurar FTP Seguro (TLS)"
        Write-Host " 5) Configurar Puerto"
        Write-Host "----------------------------------------------------"
        Write-Host " 6) Verificar Netstat"
        Write-Host " 7) Resumen de infraestructura"
        Write-Host " 8) Volver al Orquestador"
        Write-Host "===================================================="
        $opcion = Read-Host " Opcion"

        switch ($opcion) {
            "1" { Instalar-Servicio "nginx"  }
            "2" { Instalar-Servicio "apache" }
            "3" { Instalar-Servicio "iis"    }
            "4" { Configurar-FTP-Seguro }
            "5" { Validar-Puerto-Seguro }
            "6" {
                Write-Host ""; Write-Host "--- Puertos activos ---" -ForegroundColor Yellow
                $puertos = @(80,443,21,8080,8443,9090)
                if ($p -match '^\d+$') { $puertos += [int]$p }
                Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                    Where-Object { $_.LocalPort -in $puertos } |
                    Select-Object LocalAddress, LocalPort | Sort-Object LocalPort | Format-Table -AutoSize
                Pause
            }
            "7" { Mostrar-Resumen }
            "8" { return }
            default { Write-Host "Invalido" -ForegroundColor Red }
        }
    }
}
