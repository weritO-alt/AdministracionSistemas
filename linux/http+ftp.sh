#!/bin/bash

# ============================================================
#  Instalador de servicios web desde FTP
#  Fedora  |  Apache · Nginx · Tomcat
#  Flujo: FTP → descarga → valida SHA256 → instala → browser
# ============================================================

FTP_IP="192.168.114.129"
FTP_USER="chofis"
FTP_PASS="3006"
FTP_BASE="/http/Linux"
DESCARGA="/tmp/descargas_web"

mkdir -p "$DESCARGA"

# ------------------------------------------------------------
# 1. MENU PRINCIPAL
# ------------------------------------------------------------

menu_principal() {
    clear
    echo "========================================"
    echo "   INSTALADOR DE SERVICIOS WEB (FTP)   "
    echo "========================================"
    echo "1) Apache (httpd)"
    echo "2) Nginx"
    echo "3) Tomcat"
    echo "0) Salir"
    echo "----------------------------------------"
    read -rp "Elige un servicio: " opcion

    case "$opcion" in
        1) flujo_instalacion "Apache"  instalar_apache  ;;
        2) flujo_instalacion "Nginx"   instalar_nginx   ;;
        3) flujo_instalacion "Tomcat"  instalar_tomcat  ;;
        0) echo "Saliendo..."; exit 0 ;;
        *) echo "Opcion invalida."; sleep 1; menu_principal ;;
    esac
}

# ------------------------------------------------------------
# 2. PEDIR PUERTO AL USUARIO
# ------------------------------------------------------------

pedir_puerto() {
    local puerto_default="$1"
    local puerto

    while true; do
        read -rp "Puerto para el servicio [$puerto_default]: " puerto
        [[ -z "$puerto" ]] && puerto="$puerto_default"

        if ! [[ "$puerto" =~ ^[0-9]+$ ]] || \
           [ "$puerto" -lt 1 ] || [ "$puerto" -gt 65535 ]; then
            echo "Puerto invalido. Ingresa un numero entre 1 y 65535."
            continue
        fi

        if ss -tlnp | grep -q ":$puerto "; then
            echo "AVISO: El puerto $puerto ya esta en uso."
            read -rp "Usarlo de todas formas? [s/N]: " forzar
            [[ "$forzar" =~ ^[sS]$ ]] && break
        else
            break
        fi
    done

    echo "$puerto"
}

# ------------------------------------------------------------
# 3. FLUJO GENERICO
# ------------------------------------------------------------

flujo_instalacion() {
    local servicio="$1"
    local fn_instalar="$2"

    echo ""
    echo "==> Conectando al FTP: ftp://$FTP_IP$FTP_BASE/$servicio/"

    mapfile -t archivos < <(
        curl -s -l -u "$FTP_USER:$FTP_PASS" \
            "ftp://$FTP_IP$FTP_BASE/$servicio/" \
        | grep -v '\.sha256$' | grep -v '\.md5$' | grep -v '^$'
    )

    if [ ${#archivos[@]} -eq 0 ]; then
        echo "ERROR: No se encontraron archivos en el FTP para $servicio."
        read -rp "Presiona Enter..." ; menu_principal
        return
    fi

    echo ""
    echo "Archivos disponibles:"
    for i in "${!archivos[@]}"; do
        echo "  $((i+1))) ${archivos[$i]}"
    done
    echo "  0) Regresar"
    echo ""
    read -rp "Selecciona el numero: " sel

    [[ "$sel" == "0" ]] && menu_principal && return

    if ! [[ "$sel" =~ ^[0-9]+$ ]] || \
       [ "$sel" -lt 1 ] || [ "$sel" -gt "${#archivos[@]}" ]; then
        echo "Seleccion invalida."
        sleep 1; flujo_instalacion "$servicio" "$fn_instalar"
        return
    fi

    local archivo="${archivos[$((sel-1))]}"
    local url_base="ftp://$FTP_IP$FTP_BASE/$servicio"

    # SSL
    echo ""
    read -rp "Activar SSL (HTTPS)? [s/N]: " resp_ssl
    local ssl="N"
    [[ "$resp_ssl" =~ ^[sS]$ ]] && ssl="S"

    # Puerto
    echo ""
    local puerto_default=80
    [[ "$ssl" == "S" ]] && puerto_default=443
    local puerto
    puerto=$(pedir_puerto "$puerto_default")

    # Descarga
    echo ""
    echo "==> Descargando: $archivo"
    curl -s --show-error -u "$FTP_USER:$FTP_PASS" \
        "$url_base/$archivo" -o "$DESCARGA/$archivo"

    echo "==> Descargando hash SHA256..."
    curl -s -u "$FTP_USER:$FTP_PASS" \
        "$url_base/$archivo.sha256" -o "$DESCARGA/$archivo.sha256"

    # Validar
    echo "==> Validando integridad..."
    if [ -f "$DESCARGA/$archivo.sha256" ]; then
        local hash_remoto hash_local
        hash_remoto=$(awk '{print $1}' "$DESCARGA/$archivo.sha256")
        hash_local=$(sha256sum "$DESCARGA/$archivo" | awk '{print $1}')

        if [ "$hash_remoto" != "$hash_local" ]; then
            echo "ERROR: Hash no coincide. Archivo corrupto."
            echo "  Esperado:  $hash_remoto"
            echo "  Calculado: $hash_local"
            read -rp "Presiona Enter..." ; menu_principal
            return
        fi
        echo "OK: Integridad verificada."
    else
        echo "AVISO: No hay .sha256, continuando sin validacion."
    fi

    echo ""
    echo "==> Instalando $servicio en puerto $puerto..."
    "$fn_instalar" "$DESCARGA/$archivo" "$ssl" "$puerto"

    verificar_servicio "$servicio" "$ssl" "$puerto"

    read -rp "Presiona Enter para continuar..." ; menu_principal
}

# ------------------------------------------------------------
# 4. VERIFICACION FINAL
# ------------------------------------------------------------

verificar_servicio() {
    local servicio="$1"
    local ssl="$2"
    local puerto="$3"

    echo ""
    echo "==> Esperando que $servicio levante en puerto $puerto..."
    sleep 5

    if ss -tlnp | grep -q ":$puerto "; then
        local proto="http"
        [[ "$ssl" == "S" ]] && proto="https"
        echo ""
        echo "=============================================="
        echo " $servicio ACTIVO"
        echo " $proto://$FTP_IP:$puerto"
        echo "=============================================="
    else
        echo "ADVERTENCIA: El puerto $puerto no responde aun."
        echo "Revisa: sudo systemctl status $servicio"
    fi
}

# ------------------------------------------------------------
# 5. HELPERS
# ------------------------------------------------------------

detener_otros_servidores_web() {
    echo "==> Deteniendo otros servidores web..."
    sudo systemctl stop httpd  2>/dev/null
    sudo systemctl stop nginx  2>/dev/null
    sudo systemctl stop tomcat 2>/dev/null
    sudo rm -rf /var/www/html/*
    sudo mkdir -p /var/www/html
}

generar_ssl() {
    local servicio="$1"
    local dir="/etc/ssl/$servicio"
    sudo mkdir -p "$dir"
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$dir/server.key" -out "$dir/server.crt" \
        -subj "/C=MX/ST=Sinaloa/L=Los Mochis/O=Reprobados/CN=www.reprobados.com" \
        > /dev/null 2>&1
    echo "$dir"
}

obtener_version() {
    local servicio="$1"
    case "$servicio" in
        Apache)  httpd -v 2>/dev/null | grep "Server version" | awk '{print $3}' ;;
        Nginx)   nginx -v 2>&1 | awk -F/ '{print $2}' ;;
        Tomcat)  find /usr/share/tomcat* /usr/lib/tomcat* \
                      -name "RELEASE-NOTES" 2>/dev/null \
                 | head -1 \
                 | xargs grep -m1 "Apache Tomcat" 2>/dev/null \
                 | awk '{print $3}' ;;
    esac
}

# Pagina minimalista: solo texto plano, sin estilos
pagina_inicio() {
    local servicio="$1"
    local puerto="$2"
    local version="$3"

    sudo bash -c "cat > /var/www/html/index.html" <<HTML
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>$servicio</title></head>
<body>
  <p>Servicio: $servicio</p>
  <p>Puerto: $puerto</p>
  <p>Version: $version</p>
</body>
</html>
HTML
}

abrir_firewall() {
    for p in "$@"; do
        sudo firewall-cmd --permanent --add-port="$p" > /dev/null 2>&1
    done
    sudo firewall-cmd --reload > /dev/null 2>&1
}

# ------------------------------------------------------------
# 6. INSTALADORES
# ------------------------------------------------------------

instalar_apache() {
    local _archivo="$1"
    local ssl="$2"
    local puerto="$3"

    detener_otros_servidores_web
    sudo dnf install -y httpd > /dev/null
    [[ "$ssl" == "S" ]] && sudo dnf install -y mod_ssl > /dev/null

    local version; version=$(obtener_version "Apache")
    pagina_inicio "Apache" "$puerto" "$version"
    sudo chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true

    # Quitar el Listen 80 por defecto para no colisionar
    sudo sed -i "s/^Listen 80$/# Listen 80/" /etc/httpd/conf/httpd.conf 2>/dev/null || true

    if [[ "$ssl" == "S" ]]; then
        local dir; dir=$(generar_ssl "apache")
        sudo bash -c "cat > /etc/httpd/conf.d/reprobados.conf" <<CONF
Listen $puerto
<VirtualHost *:$puerto>
    ServerName www.reprobados.com
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile    $dir/server.crt
    SSLCertificateKeyFile $dir/server.key
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
CONF
    else
        sudo bash -c "cat > /etc/httpd/conf.d/reprobados.conf" <<CONF
Listen $puerto
<VirtualHost *:$puerto>
    ServerName www.reprobados.com
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
CONF
    fi

    abrir_firewall "$puerto/tcp"
    sudo systemctl enable --now httpd
    sudo systemctl restart httpd
}

instalar_nginx() {
    local _archivo="$1"
    local ssl="$2"
    local puerto="$3"

    detener_otros_servidores_web
    sudo dnf install -y nginx > /dev/null

    local version; version=$(obtener_version "Nginx")
    pagina_inicio "Nginx" "$puerto" "$version"
    sudo chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true
    sudo setsebool -P httpd_can_network_connect 1 2>/dev/null || true

    # SELinux: registrar puerto personalizado si no es estandar
    if [[ "$puerto" != "80" && "$puerto" != "443" ]]; then
        sudo semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        sudo semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null || true
    fi

    # Desactivar bloque default del nginx.conf para evitar conflictos
    sudo sed -i 's/^\s*listen\s*80\s*default_server/    # listen 80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null || true
    sudo sed -i 's/^\s*listen\s*\[::\]:80\s*default_server/    # listen [::]:80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null || true

    if [[ "$ssl" == "S" ]]; then
        local dir; dir=$(generar_ssl "nginx")
        sudo bash -c "cat > /etc/nginx/conf.d/reprobados.conf" <<CONF
server {
    listen $puerto ssl;
    server_name www.reprobados.com;
    ssl_certificate     $dir/server.crt;
    ssl_certificate_key $dir/server.key;
    root  /var/www/html;
    index index.html;
}
CONF
    else
        sudo bash -c "cat > /etc/nginx/conf.d/reprobados.conf" <<CONF
server {
    listen $puerto;
    server_name www.reprobados.com;
    root  /var/www/html;
    index index.html;
}
CONF
    fi

    abrir_firewall "$puerto/tcp"
    sudo systemctl enable --now nginx
    sudo systemctl restart nginx
}

instalar_tomcat() {
    local _archivo="$1"
    local ssl="$2"
    local puerto="$3"

    detener_otros_servidores_web
    sudo dnf install -y java-latest-openjdk tomcat > /dev/null

    local T_USER
    T_USER=$(grep -E '^tomcat' /etc/passwd | cut -d: -f1 | head -n1)
    [[ -z "$T_USER" ]] && T_USER="tomcat"

    # setcap solo si el puerto es privilegiado (< 1024)
    if [ "$puerto" -lt 1024 ]; then
        local JAVA_BIN
        JAVA_BIN=$(readlink -f "$(which java)")
        sudo setcap 'cap_net_bind_service=+ep' "$JAVA_BIN"
    fi

    local version; version=$(obtener_version "Tomcat")
    pagina_inicio "Tomcat" "$puerto" "$version"
    sudo mkdir -p /var/lib/tomcat/webapps/ROOT
    sudo cp /var/www/html/index.html /var/lib/tomcat/webapps/ROOT/index.html
    sudo chown -R "$T_USER:$T_USER" /var/lib/tomcat/webapps/ROOT

    if [[ "$ssl" == "S" ]]; then
        local dir; dir=$(generar_ssl "tomcat")
        local ks="/etc/ssl/tomcat/keystore.p12"
        sudo openssl pkcs12 -export \
            -in "$dir/server.crt" -inkey "$dir/server.key" \
            -out "$ks" -name tomcat -passout pass:reprobados > /dev/null 2>&1
        sudo chown "$T_USER:$T_USER" "$ks"

        sudo bash -c "cat > /etc/tomcat/server.xml" <<XML
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$puerto"
               protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true">
      <SSLHostConfig>
        <Certificate certificateKeystoreFile="$ks"
                     type="RSA"
                     certificateKeystorePassword="reprobados"/>
      </SSLHostConfig>
    </Connector>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps"
            unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>
XML
    else
        sudo bash -c "cat > /etc/tomcat/server.xml" <<XML
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$puerto" protocol="HTTP/1.1" connectionTimeout="20000"/>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps"
            unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>
XML
    fi

    abrir_firewall "$puerto/tcp"
    sudo systemctl enable --now tomcat
    sudo systemctl restart tomcat
    sleep 8
}

# ------------------------------------------------------------
# INICIO
# ------------------------------------------------------------
menu_principal
