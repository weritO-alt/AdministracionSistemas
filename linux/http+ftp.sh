#!/bin/bash
# ============================================================
#  ORQUESTADOR HÍBRIDO DE SERVICIOS - FEDORA SERVER
#  Servicios: Apache (httpd), Nginx, Tomcat, vsftpd
# ============================================================

# --- CONFIGURACIÓN GLOBAL FTP ---
FTP_SERVER="192.168.114.129"
FTP_USER="chofis"
FTP_PASS="3006"

# --- VARIABLES GLOBALES ---
RESUMEN_INSTALACIONES=()
PAQUETE_DESCARGADO=""
fuente=""
activar_ssl=""
archivo_a_instalar=""

# ============================================================
#  BLOQUE 1: UTILIDADES GENERALES
# ============================================================

# Abre los puertos necesarios usando firewall-cmd (Fedora)
abrir_puerto_firewall() {
    local puerto=$1
    local proto=${2:-tcp}
    sudo firewall-cmd --permanent --add-port="${puerto}/${proto}" > /dev/null 2>&1
}

recargar_firewall() {
    sudo firewall-cmd --reload > /dev/null 2>&1
}

# Detiene Apache y Nginx para liberar puertos 80/443 antes de instalar
liberar_puertos_web() {
    echo "Liberando puertos y limpiando entorno..."
    sudo systemctl stop httpd   > /dev/null 2>&1
    sudo systemctl stop nginx   > /dev/null 2>&1
    sudo systemctl stop tomcat  > /dev/null 2>&1
    sudo rm -rf /var/www/html/*
    sudo mkdir -p /var/www/html
}

# Genera un certificado SSL autofirmado en /etc/ssl/<servicio>/
generar_ssl() {
    local servicio=$1
    local cert_dir="/etc/ssl/$servicio"
    sudo mkdir -p "$cert_dir"
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$cert_dir/server.key" \
        -out    "$cert_dir/server.crt" \
        -subj "/C=MX/ST=Sinaloa/L=Los Mochis/O=Reprobados/CN=www.reprobados.com" \
        > /dev/null 2>&1
    echo "$cert_dir"
}

# Crea una página de prueba visual indicando el servidor y si tiene SSL
actualizar_index_visual() {
    local servidor=$1
    local ssl_status=$2
    local color="red"
    local msg="SITIO NO SEGURO (HTTP)"
    local puerto="80"
    if [[ "$ssl_status" == "S" ]]; then
        color="green"; msg="SITIO SEGURO (HTTPS)"; puerto="443"
    fi
    sudo bash -c "cat > /var/www/html/index.html" <<EOF
<html>
<body style='font-family: sans-serif; text-align: center; padding: 50px;'>
    <h1 style='color: $color;'>Servicio activo: $servidor</h1>
    <h2 style='background: $color; color: white; padding: 10px;'>$msg</h2>
    <p>Dominio: www.reprobados.com</p>
    <p>Puerto: $puerto</p>
</body>
</html>
EOF
}

# ============================================================
#  BLOQUE 2: DESCARGA Y VALIDACIÓN DESDE FTP
# ============================================================

# Descarga un binario y su .sha256 desde el FTP privado y valida integridad
descargar_y_validar_hash() {
    local servicio=$1
    local archivo=$2
    local ruta="ftp://$FTP_SERVER/http/Linux/$servicio/"
    cd /tmp || exit 1
    echo "Descargando $archivo desde el FTP..."
    curl -s -u "$FTP_USER:$FTP_PASS" -O "${ruta}${archivo}"
    curl -s -u "$FTP_USER:$FTP_PASS" -O "${ruta}${archivo}.sha256"

    if [[ ! -f "${archivo}.sha256" ]]; then
        echo "Advertencia: No se encontró archivo .sha256. Saltando validación."
        return 0
    fi

    local hash_remoto
    hash_remoto=$(awk '{print $1}' "${archivo}.sha256")
    local hash_local
    hash_local=$(sha256sum "$archivo" | awk '{print $1}')

    if [[ "$hash_remoto" != "$hash_local" ]]; then
        echo "ERROR DE INTEGRIDAD: El hash SHA256 no coincide. Abortando." >&2
        return 1
    fi
    echo "Validación SHA256 exitosa."
}

# Navegación interactiva por el FTP para elegir servicio y versión
navegar_y_descargar_ftp() {
    local ftp_user="linux"
    local ftp_pass="1234"
    local ip_servidor="192.168.114.129"
    local base_path="/http/Linux"
    local url_base="ftps://$ip_servidor$base_path/"
    local dir_descargas="/tmp/descargas_ftp"

    mkdir -p "$dir_descargas"

    echo "--------------------------------------------------"
    echo " Conectando al FTP -> $base_path"
    echo " Listando carpetas de servicios disponibles..."
    echo "--------------------------------------------------"

    mapfile -t carpetas_servicios < <(
        curl -s -l --insecure -u "$ftp_user:$ftp_pass" "$url_base"
    )

    if [[ ${#carpetas_servicios[@]} -eq 0 ]]; then
        echo "Error: No se encontraron carpetas en el repositorio." >&2
        return 1
    fi

    for i in "${!carpetas_servicios[@]}"; do
        echo "$((i+1))) $(echo "${carpetas_servicios[$i]}" | tr -d '\r')"
    done

    read -r -p "Selecciona el número de la carpeta: " sel_serv
    local servicio_elegido
    servicio_elegido=$(echo "${carpetas_servicios[$((sel_serv-1))]}" | tr -d '\r')
    local url_versiones="${url_base}${servicio_elegido}/"

    echo "--------------------------------------------------"
    echo " Entrando a /$servicio_elegido"
    echo " Listando archivos binarios disponibles..."
    echo "--------------------------------------------------"

    mapfile -t archivos_versiones < <(
        curl -s -l --insecure -u "$ftp_user:$ftp_pass" "$url_versiones" \
        | grep -v '\.sha256$' | grep -v '\.md5$'
    )

    if [[ ${#archivos_versiones[@]} -eq 0 ]]; then
        echo "No se encontraron archivos binarios." >&2
        return 1
    fi

    for i in "${!archivos_versiones[@]}"; do
        echo "$((i+1))) $(echo "${archivos_versiones[$i]}" | tr -d '\r')"
    done

    read -r -p "Selecciona la versión a descargar: " sel_ver
    local archivo_elegido
    archivo_elegido=$(echo "${archivos_versiones[$((sel_ver-1))]}" | tr -d '\r')

    echo "Descargando y validando $archivo_elegido ..."
    curl -s --show-error --insecure \
        -u "$ftp_user:$ftp_pass" \
        "$url_versiones$archivo_elegido" \
        -o "$dir_descargas/$archivo_elegido"

    curl -s --show-error --insecure \
        -u "$ftp_user:$ftp_pass" \
        "$url_versiones$archivo_elegido.sha256" \
        -o "$dir_descargas/$archivo_elegido.sha256"

    cd "$dir_descargas" || return 1
    if sha256sum -c "$archivo_elegido.sha256" > /dev/null 2>&1; then
        echo "Validación SHA256 exitosa."
        PAQUETE_DESCARGADO="$dir_descargas/$archivo_elegido"
        cd - > /dev/null || return 1
        return 0
    else
        echo "Error: El archivo está corrupto o incompleto." >&2
        cd - > /dev/null || return 1
        return 1
    fi
}

# ============================================================
#  BLOQUE 3: INSTALADORES DE SERVICIOS (FEDORA / DNF)
# ============================================================

instalar_apache() {
    local archivo=$1
    local web_ftp=$2
    local ssl=$3

    liberar_puertos_web
    [[ "$web_ftp" == "FTP" ]] && descargar_y_validar_hash "Apache" "$archivo"

    echo "Instalando httpd (Apache) en Fedora..."
    sudo dnf install -y httpd > /dev/null

    actualizar_index_visual "Apache (httpd)" "$ssl"

    # Crear vhost limpio (desactivar el default primero)
    sudo bash -c 'cat > /etc/httpd/conf.d/reprobados.conf' <<'CONFEOF'
CONFEOF

    if [[ "$ssl" == "S" ]]; then
        sudo dnf install -y mod_ssl > /dev/null
        local dir
        dir=$(generar_ssl "apache")
        sudo bash -c "cat > /etc/httpd/conf.d/reprobados.conf" <<EOF
<VirtualHost *:80>
    ServerName www.reprobados.com
    Redirect permanent / https://www.reprobados.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName www.reprobados.com
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile    $dir/server.crt
    SSLCertificateKeyFile $dir/server.key
</VirtualHost>
EOF
        abrir_puerto_firewall 443
    else
        sudo bash -c "cat > /etc/httpd/conf.d/reprobados.conf" <<'EOF'
<VirtualHost *:80>
    ServerName www.reprobados.com
    DocumentRoot /var/www/html
</VirtualHost>
EOF
    fi

    # SELinux: permitir que httpd sirva desde /var/www/html
    sudo setsebool -P httpd_read_user_content 1 > /dev/null 2>&1

    abrir_puerto_firewall 80
    recargar_firewall

    sudo systemctl enable --now httpd
    sudo systemctl restart httpd
    RESUMEN_INSTALACIONES+=("Apache (httpd) -> Completado (SSL: $ssl)")
}

instalar_nginx() {
    local archivo=$1
    local web_ftp=$2
    local ssl=$3

    liberar_puertos_web
    [[ "$web_ftp" == "FTP" ]] && descargar_y_validar_hash "Nginx" "$archivo"

    echo "Instalando Nginx en Fedora..."
    sudo dnf install -y nginx > /dev/null

    actualizar_index_visual "Nginx" "$ssl"

    if [[ "$ssl" == "S" ]]; then
        local dir
        dir=$(generar_ssl "nginx")
        sudo bash -c "cat > /etc/nginx/conf.d/reprobados.conf" <<EOF
server {
    listen 80;
    server_name www.reprobados.com;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name www.reprobados.com;
    ssl_certificate     $dir/server.crt;
    ssl_certificate_key $dir/server.key;
    root  /var/www/html;
    index index.html;
}
EOF
        abrir_puerto_firewall 443
    else
        sudo bash -c "cat > /etc/nginx/conf.d/reprobados.conf" <<'EOF'
server {
    listen 80;
    server_name www.reprobados.com;
    root  /var/www/html;
    index index.html;
}
EOF
    fi

    abrir_puerto_firewall 80
    recargar_firewall

    sudo systemctl enable --now nginx
    sudo systemctl restart nginx
    RESUMEN_INSTALACIONES+=("Nginx -> Completado (SSL: $ssl)")
}

instalar_tomcat() {
    local archivo=$1
    local web_ftp=$2
    local ssl=$3

    liberar_puertos_web
    [[ "$web_ftp" == "FTP" ]] && descargar_y_validar_hash "Tomcat" "$archivo"

    echo "Instalando Tomcat y Java en Fedora..."
    sudo dnf install -y java-17-openjdk tomcat > /dev/null

    # Detectar usuario del servicio tomcat
    local T_USER
    T_USER=$(grep -E '^tomcat' /etc/passwd | cut -d: -f1 | head -n1)
    [[ -z "$T_USER" ]] && T_USER="tomcat"
    echo "Usuario del servicio Tomcat: $T_USER"

    # En Fedora no hay authbind en repos estándar.
    # Usamos override de systemd para CAP_NET_BIND_SERVICE (puertos < 1024 sin root)
    sudo mkdir -p /etc/systemd/system/tomcat.service.d/
    sudo bash -c 'cat > /etc/systemd/system/tomcat.service.d/override.conf' <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF
    sudo systemctl daemon-reload

    # Contenido de prueba
    actualizar_index_visual "Tomcat" "$ssl"
    sudo mkdir -p /var/lib/tomcat/webapps/ROOT
    sudo cp /var/www/html/index.html /var/lib/tomcat/webapps/ROOT/index.html
    sudo chown -R "$T_USER:$T_USER" /var/lib/tomcat/webapps/ROOT

    if [[ "$ssl" == "S" ]]; then
        local dir
        dir=$(generar_ssl "tomcat")
        local ks="/etc/ssl/tomcat/keystore.p12"
        sudo openssl pkcs12 -export \
            -in   "$dir/server.crt" \
            -inkey "$dir/server.key" \
            -out  "$ks" \
            -name tomcat \
            -passout pass:reprobados > /dev/null 2>&1
        sudo chown "$T_USER:$T_USER" "$ks"

        sudo bash -c "cat > /etc/tomcat/server.xml" <<EOF
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="80"  protocol="HTTP/1.1" connectionTimeout="20000" redirectPort="443" />
    <Connector port="443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true">
      <SSLHostConfig>
        <Certificate certificateKeystoreFile="$ks"
                     type="RSA"
                     certificateKeystorePassword="reprobados" />
      </SSLHostConfig>
    </Connector>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true" />
    </Engine>
  </Service>
</Server>
EOF
        abrir_puerto_firewall 443
    else
        sudo bash -c 'cat > /etc/tomcat/server.xml' <<'EOF'
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="80" protocol="HTTP/1.1" connectionTimeout="20000" />
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true" />
    </Engine>
  </Service>
</Server>
EOF
    fi

    abrir_puerto_firewall 80
    recargar_firewall

    sudo systemctl enable --now tomcat
    sudo systemctl restart tomcat
    echo "Esperando que Tomcat levante (10s)..."
    sleep 10
    RESUMEN_INSTALACIONES+=("Tomcat -> Completado (SSL: $ssl)")
}

instalar_vsftpd() {
    local archivo=$1
    local web_ftp=$2
    local ssl=$3

    echo "Instalando vsftpd en Fedora..."
    [[ "$web_ftp" == "FTP" ]] && descargar_y_validar_hash "vsftpd" "$archivo"
    sudo dnf install -y vsftpd openssl > /dev/null

    # Asegurar shell válida para usuarios locales
    grep -q "/bin/bash" /etc/shells || sudo bash -c "echo /bin/bash >> /etc/shells"

    # Estructura de directorios
    sudo mkdir -p /srv/ftp/{anon,autenticados,grupos/general,grupos/reprobados,grupos/recursadores}

    # Certificados
    sudo mkdir -p /etc/vsftpd/ssl
    if [[ "$ssl" == "S" ]]; then
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/vsftpd/ssl/vsftpd.key \
            -out    /etc/vsftpd/ssl/vsftpd.crt \
            -subj "/C=MX/ST=Sinaloa/L=Los Mochis/O=Reprobados/CN=www.reprobados.com" \
            > /dev/null 2>&1
    fi

    # Configuración base (las variables con $ van escapadas para que vsftpd las expanda)
    sudo bash -c 'cat > /etc/vsftpd/vsftpd.conf' <<'EOF'
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

# Enjaular usuarios en su directorio
chroot_local_user=YES
allow_writeable_chroot=YES
user_sub_token=$USER
local_root=/srv/ftp/autenticados/$USER

# Modo pasivo
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000
pasv_address=192.168.114.129
EOF

    if [[ "$ssl" == "S" ]]; then
        sudo bash -c 'cat >> /etc/vsftpd/vsftpd.conf' <<'EOF'

# Túnel FTPS implícito
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
EOF
        abrir_puerto_firewall 990
    else
        sudo bash -c 'cat >> /etc/vsftpd/vsftpd.conf' <<'EOF'

# Acceso anónimo (solo sin SSL)
anonymous_enable=YES
anon_root=/srv/ftp/anon
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
EOF
    fi

    # SELinux: permitir vsftpd con home dirs y modo pasivo
    sudo setsebool -P ftpd_full_access 1       > /dev/null 2>&1
    sudo setsebool -P ftp_home_dir    1       > /dev/null 2>&1

    abrir_puerto_firewall 20
    abrir_puerto_firewall 21
    abrir_puerto_firewall "40000-50000"
    recargar_firewall

    sudo systemctl enable --now vsftpd
    sudo systemctl restart vsftpd
    RESUMEN_INSTALACIONES+=("vsftpd -> Completado (SSL: $ssl)")
}

# ============================================================
#  BLOQUE 4: MENÚ Y ORQUESTADOR
# ============================================================

mostrar_menu() {
    clear
    echo "=========================================================="
    echo "      ORQUESTADOR HÍBRIDO DE SERVICIOS - FEDORA SERVER    "
    echo "=========================================================="
    echo "  1) Apache (httpd)"
    echo "  2) Nginx"
    echo "  3) Tomcat"
    echo "  4) vsftpd"
    echo "  5) Salir y mostrar resumen final"
    echo "=========================================================="
    read -r -p "Seleccione el servicio a instalar: " opcion
    echo ""
}

preguntar_fuente_y_ssl() {
    local servicio=$1
    echo "----------------------------------------------------------"
    echo " Configuración para: $servicio"
    echo "----------------------------------------------------------"
    echo " 1) WEB  (instala directamente con dnf)"
    echo " 2) FTP  (repositorio privado con validación SHA256)"
    read -r -p "Fuente de instalación: " fuente_opcion

    if [[ "$fuente_opcion" == "2" ]]; then
        fuente="FTP"
        navegar_y_descargar_ftp
        if [[ $? -ne 0 ]]; then
            echo "No se pudo obtener el instalador desde el FTP."
            read -r -p "Presiona ENTER para volver al menú..."
            return 1
        fi
        archivo_a_instalar="$PAQUETE_DESCARGADO"
    else
        fuente="WEB"
        archivo_a_instalar=""
    fi

    echo ""
    read -r -p "¿Activar SSL en este servicio? [S/N]: " activar_ssl
    activar_ssl=$(echo "$activar_ssl" | tr '[:lower:]' '[:upper:]')
    return 0
}

mostrar_resumen_final() {
    echo ""
    echo "=========================================================="
    echo "           RESUMEN DE INSTALACIONES REALIZADAS            "
    echo "=========================================================="
    if [[ ${#RESUMEN_INSTALACIONES[@]} -eq 0 ]]; then
        echo "  (No se realizó ninguna instalación en esta sesión)"
    else
        for r in "${RESUMEN_INSTALACIONES[@]}"; do
            echo "  -> $r"
        done
    fi
    echo "=========================================================="
    echo ""
}

# ============================================================
#  PUNTO DE ENTRADA - BUCLE PRINCIPAL
# ============================================================

while true; do
    mostrar_menu

    case $opcion in
        1)
            preguntar_fuente_y_ssl "Apache"
            [[ $? -eq 0 ]] && instalar_apache "$archivo_a_instalar" "$fuente" "$activar_ssl"
            ;;
        2)
            preguntar_fuente_y_ssl "Nginx"
            [[ $? -eq 0 ]] && instalar_nginx "$archivo_a_instalar" "$fuente" "$activar_ssl"
            ;;
        3)
            preguntar_fuente_y_ssl "Tomcat"
            [[ $? -eq 0 ]] && instalar_tomcat "$archivo_a_instalar" "$fuente" "$activar_ssl"
            ;;
        4)
            preguntar_fuente_y_ssl "vsftpd"
            [[ $? -eq 0 ]] && instalar_vsftpd "$archivo_a_instalar" "$fuente" "$activar_ssl"
            ;;
        5)
            mostrar_resumen_final
            exit 0
            ;;
        *)
            echo "Opción no válida."
            sleep 2
            continue
            ;;
    esac

    echo ""
    read -r -p "¿Instalar otro servicio? [S/N]: " continuar
    continuar=$(echo "$continuar" | tr '[:lower:]' '[:upper:]')
    if [[ "$continuar" == "N" ]]; then
        mostrar_resumen_final
        exit 0
    fi
done
