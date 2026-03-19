#!/bin/bash

# ============================================================
#  Practica 7 - Orquestador de instalacion hibrida
#  Fedora | Apache · Nginx · Tomcat · vsftpd
#  Fuentes: WEB (dnf) o FTPS (repositorio privado)
# ============================================================

FTP_IP="192.168.114.129"
FTP_USER="chofis"
FTP_PASS="3006"
FTP_BASE="/http/Linux"          # Ruta dentro del servidor FTP
FTP_PORT="990"                  # Puerto FTPS implicito
DESCARGA="/tmp/descargas_web"
RESUMEN=()

mkdir -p "$DESCARGA"

# ============================================================
# MENU PRINCIPAL
# ============================================================

menu_principal() {
    clear
    echo "========================================================"
    echo "   ORQUESTADOR DE INSTALACION - LINUX (FEDORA)         "
    echo "========================================================"
    echo "1) Apache (httpd)"
    echo "2) Nginx"
    echo "3) Tomcat"
    echo "4) vsftpd (FTP/FTPS)"
    echo "5) Ver resumen de instalaciones"
    echo "0) Salir"
    echo "--------------------------------------------------------"
    read -rp "Elige un servicio: " opcion

    case "$opcion" in
        1) flujo_instalacion "Apache"  instalar_apache  ;;
        2) flujo_instalacion "Nginx"   instalar_nginx   ;;
        3) flujo_instalacion "Tomcat"  instalar_tomcat  ;;
        4) flujo_instalacion "vsftpd"  instalar_vsftpd  ;;
        5) mostrar_resumen ;;
        0) echo "Saliendo..."; exit 0 ;;
        *) echo "Opcion invalida."; sleep 1; menu_principal ;;
    esac
}

# ============================================================
# ELEGIR FUENTE: WEB o FTPS
# ============================================================

elegir_fuente() {
    echo ""
    echo "Fuente de instalacion:"
    echo "  1) WEB  - gestor de paquetes (dnf)"
    echo "  2) FTPS - repositorio privado ($FTP_IP:$FTP_PORT)"
    read -rp "Elige [1/2]: " fuente
    case "$fuente" in
        2) echo "FTPS" ;;
        *) echo "WEB"  ;;
    esac
}

# ============================================================
# NAVEGACION FTPS con curl
# --ssl-reqd  : exige cifrado TLS
# --insecure  : acepta certificado autofirmado
# ============================================================

navegar_ftps() {
    local servicio="$1"
    ARCHIVO_LOCAL=""

    local url_dir="ftps://$FTP_IP:$FTP_PORT$FTP_BASE/$servicio/"

    echo ""
    echo "==> Conectando al FTPS: $url_dir"

    # Listar archivos (excluye hashes y lineas vacias)
    mapfile -t archivos < <(
        curl -s -l --ssl-reqd --insecure \
            -u "$FTP_USER:$FTP_PASS" "$url_dir" \
        | grep -v '\.sha256$' | grep -v '\.md5$' | grep -v '^$'
    )

    if [ ${#archivos[@]} -eq 0 ]; then
        echo "ERROR: No se encontraron archivos en FTPS para $servicio."
        echo "Verifica que el servidor FTP este corriendo y la ruta sea correcta."
        return 1
    fi

    echo "Archivos disponibles:"
    for i in "${!archivos[@]}"; do
        echo "  $((i+1))) ${archivos[$i]}"
    done
    echo "  0) Regresar"
    echo ""
    read -rp "Selecciona el numero: " sel

    [[ "$sel" == "0" ]] && return 1

    if ! [[ "$sel" =~ ^[0-9]+$ ]] || \
       [ "$sel" -lt 1 ] || [ "$sel" -gt "${#archivos[@]}" ]; then
        echo "Seleccion invalida."
        return 1
    fi

    local archivo="${archivos[$((sel-1))]}"

    # Descargar RPM
    echo ""
    echo "==> Descargando: $archivo"
    curl -s --show-error --ssl-reqd --insecure \
        -u "$FTP_USER:$FTP_PASS" \
        "$url_dir$archivo" \
        -o "$DESCARGA/$archivo"

    # Descargar hash
    echo "==> Descargando hash SHA256..."
    curl -s --ssl-reqd --insecure \
        -u "$FTP_USER:$FTP_PASS" \
        "$url_dir$archivo.sha256" \
        -o "$DESCARGA/$archivo.sha256"

    # Validar integridad
    echo "==> Validando integridad SHA256..."
    if [ -f "$DESCARGA/$archivo.sha256" ]; then
        local hash_remoto hash_local
        hash_remoto=$(awk '{print $1}' "$DESCARGA/$archivo.sha256")
        hash_local=$(sha256sum "$DESCARGA/$archivo" | awk '{print $1}')

        if [ "$hash_remoto" != "$hash_local" ]; then
            echo "ERROR: Hash no coincide. Archivo corrupto."
            echo "  Esperado:  $hash_remoto"
            echo "  Calculado: $hash_local"
            RESUMEN+=("HASH FALLIDO | $servicio | $archivo")
            return 1
        fi
        echo "OK: Integridad verificada."
        RESUMEN+=("Hash OK | $servicio | $archivo")
    else
        echo "AVISO: Sin archivo .sha256, continuando sin validacion."
    fi

    ARCHIVO_LOCAL="$DESCARGA/$archivo"
    return 0
}

# ============================================================
# FLUJO GENERICO
# ============================================================

flujo_instalacion() {
    local servicio="$1"
    local fn_instalar="$2"

    local fuente
    fuente=$(elegir_fuente)

    local archivo_local=""
    if [[ "$fuente" == "FTPS" ]]; then
        navegar_ftps "$servicio" || { read -rp "Presiona Enter..."; menu_principal; return; }
        archivo_local="$ARCHIVO_LOCAL"
    fi

    echo ""
    read -rp "Activar SSL en este servicio? [S/N]: " resp_ssl
    local ssl="N"
    [[ "$resp_ssl" =~ ^[sS]$ ]] && ssl="S"

    echo ""
    local puerto_default=80
    [[ "$ssl" == "S" ]] && puerto_default=443
    local puerto
    puerto=$(pedir_puerto "$puerto_default")

    echo ""
    echo "==> Instalando $servicio | Fuente: $fuente | Puerto: $puerto | SSL: $ssl"
    "$fn_instalar" "$archivo_local" "$fuente" "$ssl" "$puerto"

    verificar_servicio "$servicio" "$ssl" "$puerto"

    read -rp "Presiona Enter para continuar..." ; menu_principal
}

# ============================================================
# PEDIR PUERTO
# ============================================================

pedir_puerto() {
    local puerto_default="$1"
    local puerto

    while true; do
        read -rp "Puerto para el servicio [$puerto_default]: " puerto
        [[ -z "$puerto" ]] && puerto="$puerto_default"

        if ! [[ "$puerto" =~ ^[0-9]+$ ]] || \
           [ "$puerto" -lt 1 ] || [ "$puerto" -gt 65535 ]; then
            echo "Puerto invalido."
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

# ============================================================
# VERIFICACION Y RESUMEN
# ============================================================

verificar_servicio() {
    local servicio="$1"
    local ssl="$2"
    local puerto="$3"

    echo ""
    echo "==> Verificando $servicio en puerto $puerto..."
    sleep 4

    local proto="http"
    [[ "$ssl" == "S" ]] && proto="https"

    if ss -tlnp | grep -q ":$puerto "; then
        echo ""
        echo "=============================================="
        echo " OK: $servicio activo"
        echo " Abre: $proto://$FTP_IP:$puerto"
        echo "=============================================="
        RESUMEN+=("OK    | $servicio | Puerto $puerto | SSL: $ssl | $proto://$FTP_IP:$puerto")
    else
        echo "FALLO: El puerto $puerto no responde."
        echo "Revisa: sudo systemctl status $servicio"
        RESUMEN+=("FALLO | $servicio | Puerto $puerto | SSL: $ssl")
    fi
}

mostrar_resumen() {
    clear
    echo "========================================================"
    echo "         RESUMEN AUTOMATIZADO DE INSTALACIONES          "
    echo "========================================================"
    if [ ${#RESUMEN[@]} -eq 0 ]; then
        echo "  Sin instalaciones registradas en esta sesion."
    else
        for linea in "${RESUMEN[@]}"; do
            echo "  -> $linea"
        done
    fi
    echo "========================================================"
    read -rp "Presiona Enter para continuar..." ; menu_principal
}

# ============================================================
# HELPERS
# ============================================================

detener_servidores_web() {
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
        -keyout "$dir/server.key" \
        -out    "$dir/server.crt" \
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
                      -name "RELEASE-NOTES" 2>/dev/null | head -1 \
                 | xargs grep -m1 "Apache Tomcat" 2>/dev/null | awk '{print $3}' ;;
        vsftpd)  vsftpd -v 2>&1 | awk '{print $NF}' ;;
    esac
}

# Pagina minimalista visible en el navegador
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

registrar_puerto_selinux() {
    local puerto="$1"
    if [[ "$puerto" != "80" && "$puerto" != "443" ]]; then
        sudo semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        sudo semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null || true
    fi
}

# ============================================================
# APACHE
# ============================================================

instalar_apache() {
    local archivo="$1"; local fuente="$2"; local ssl="$3"; local puerto="$4"

    detener_servidores_web

    if [[ "$fuente" == "FTPS" && -f "$archivo" ]]; then
        echo "==> Instalando desde RPM descargado..."
        sudo dnf install -y "$archivo" > /dev/null
    else
        sudo dnf install -y httpd > /dev/null
    fi
    [[ "$ssl" == "S" ]] && sudo dnf install -y mod_ssl > /dev/null

    local version; version=$(obtener_version "Apache")
    pagina_inicio "Apache" "$puerto" "$version"
    sudo chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true
    sudo sed -i "s/^Listen 80$/# Listen 80/" /etc/httpd/conf/httpd.conf 2>/dev/null || true

    if [[ "$ssl" == "S" ]]; then
        local dir; dir=$(generar_ssl "apache")
        sudo bash -c "cat > /etc/httpd/conf.d/reprobados.conf" <<CONF
Listen 80
Listen $puerto
<VirtualHost *:80>
    ServerName www.reprobados.com
    Redirect permanent / https://www.reprobados.com:$puerto/
</VirtualHost>
<VirtualHost *:$puerto>
    ServerName www.reprobados.com
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile    $dir/server.crt
    SSLCertificateKeyFile $dir/server.key
    Header always set Strict-Transport-Security "max-age=31536000"
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
CONF
        abrir_firewall 80/tcp "$puerto/tcp"
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
        abrir_firewall "$puerto/tcp"
    fi

    sudo systemctl enable --now httpd
    sudo systemctl restart httpd
}

# ============================================================
# NGINX
# ============================================================

instalar_nginx() {
    local archivo="$1"; local fuente="$2"; local ssl="$3"; local puerto="$4"

    detener_servidores_web

    if [[ "$fuente" == "FTPS" && -f "$archivo" ]]; then
        echo "==> Instalando desde RPM descargado..."
        sudo dnf install -y "$archivo" > /dev/null
    else
        sudo dnf install -y nginx > /dev/null
    fi

    local version; version=$(obtener_version "Nginx")
    pagina_inicio "Nginx" "$puerto" "$version"
    sudo chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true
    sudo setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    registrar_puerto_selinux "$puerto"

    sudo sed -i 's/^\s*listen\s*80\s*default_server/    # listen 80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null || true
    sudo sed -i 's/^\s*listen\s*\[::\]:80\s*default_server/    # listen [::]:80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null || true

    if [[ "$ssl" == "S" ]]; then
        local dir; dir=$(generar_ssl "nginx")
        sudo bash -c "cat > /etc/nginx/conf.d/reprobados.conf" <<CONF
server {
    listen 80;
    server_name www.reprobados.com;
    return 301 https://\$host:$puerto\$request_uri;
}
server {
    listen $puerto ssl;
    server_name www.reprobados.com;
    ssl_certificate     $dir/server.crt;
    ssl_certificate_key $dir/server.key;
    add_header Strict-Transport-Security "max-age=31536000" always;
    root  /var/www/html;
    index index.html;
}
CONF
        abrir_firewall 80/tcp "$puerto/tcp"
    else
        sudo bash -c "cat > /etc/nginx/conf.d/reprobados.conf" <<CONF
server {
    listen $puerto;
    server_name www.reprobados.com;
    root  /var/www/html;
    index index.html;
}
CONF
        abrir_firewall "$puerto/tcp"
    fi

    sudo systemctl enable --now nginx
    sudo systemctl restart nginx
}

# ============================================================
# TOMCAT
# ============================================================

instalar_tomcat() {
    local archivo="$1"; local fuente="$2"; local ssl="$3"; local puerto="$4"

    detener_servidores_web

    if [[ "$fuente" == "FTPS" && -f "$archivo" ]]; then
        echo "==> Instalando desde RPM descargado..."
        sudo dnf install -y "$archivo" > /dev/null
    else
        sudo dnf install -y java-latest-openjdk tomcat > /dev/null
    fi

    local T_USER
    T_USER=$(grep -E '^tomcat' /etc/passwd | cut -d: -f1 | head -n1)
    [[ -z "$T_USER" ]] && T_USER="tomcat"

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
    <Connector port="80" protocol="HTTP/1.1"
               connectionTimeout="20000" redirectPort="$puerto"/>
    <Connector port="$puerto"
               protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true">
      <SSLHostConfig>
        <Certificate certificateKeystoreFile="$ks"
                     type="RSA" certificateKeystorePassword="reprobados"/>
      </SSLHostConfig>
    </Connector>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps"
            unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>
XML
        abrir_firewall 80/tcp "$puerto/tcp"
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
        abrir_firewall "$puerto/tcp"
    fi

    sudo systemctl enable --now tomcat
    sudo systemctl restart tomcat
    sleep 8
}

# ============================================================
# VSFTPD
# ============================================================

instalar_vsftpd() {
    local archivo="$1"; local fuente="$2"; local ssl="$3"; local _puerto="$4"

    if [[ "$fuente" == "FTPS" && -f "$archivo" ]]; then
        echo "==> Instalando desde RPM descargado..."
        sudo dnf install -y "$archivo" > /dev/null
    else
        sudo dnf install -y vsftpd openssl > /dev/null
    fi

    grep -q "/bin/bash" /etc/shells || \
        sudo bash -c "echo /bin/bash >> /etc/shells"

    sudo mkdir -p /srv/ftp/{anon,autenticados,grupos/general,grupos/reprobados,grupos/recursadores}
    sudo chmod 755 /srv/ftp/autenticados
    sudo chown root:root /srv/ftp/autenticados

    sudo mkdir -p /etc/vsftpd/ssl

    if [[ "$ssl" == "S" ]]; then
        echo "==> Generando certificado FTPS..."
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/vsftpd/ssl/vsftpd.key \
            -out    /etc/vsftpd/ssl/vsftpd.crt \
            -subj "/C=MX/ST=Sinaloa/L=Los Mochis/O=Reprobados/CN=www.reprobados.com" \
            > /dev/null 2>&1
        sudo chmod 600 /etc/vsftpd/ssl/vsftpd.key
    fi

    sudo bash -c "cat > /etc/vsftpd/vsftpd.conf" <<CONF
local_enable=YES
write_enable=YES
local_umask=002
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
listen=YES
listen_ipv6=NO
pam_service_name=vsftpd
user_sub_token=\$USER
chroot_local_user=YES
allow_writeable_chroot=YES
local_root=/srv/ftp/autenticados/\$USER
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000
pasv_address=$FTP_IP
CONF

    if [[ "$ssl" == "S" ]]; then
        sudo bash -c "cat >> /etc/vsftpd/vsftpd.conf" <<CONF
listen_port=990
implicit_ssl=YES
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
rsa_cert_file=/etc/vsftpd/ssl/vsftpd.crt
rsa_private_key_file=/etc/vsftpd/ssl/vsftpd.key
CONF
        abrir_firewall 990/tcp 40000-50000/tcp
    else
        sudo bash -c "cat >> /etc/vsftpd/vsftpd.conf" <<CONF
anonymous_enable=YES
anon_root=/srv/ftp/anon
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
CONF
        abrir_firewall 20/tcp 21/tcp 40000-50000/tcp
    fi

    sudo setsebool -P ftpd_full_access 1 2>/dev/null || true
    sudo systemctl enable --now vsftpd
    sudo systemctl restart vsftpd

    local puerto_ftp=21
    [[ "$ssl" == "S" ]] && puerto_ftp=990
    sleep 3

    if ss -tlnp | grep -q ":$puerto_ftp "; then
        echo "OK: vsftpd activo en puerto $puerto_ftp"
        RESUMEN+=("OK    | vsftpd | Puerto $puerto_ftp | SSL: $ssl")
    else
        echo "FALLO: vsftpd no responde en puerto $puerto_ftp"
        RESUMEN+=("FALLO | vsftpd | Puerto $puerto_ftp | SSL: $ssl")
    fi
}

# ============================================================
# INICIO
# ============================================================
menu_principal
