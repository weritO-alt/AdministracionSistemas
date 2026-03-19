#!/usr/bin/env bash
# ============================================================
#  main.sh  -  Practica 7: Orquestador Linux (FEDORA)
#  Un solo archivo, sin modularizacion
#  Servicios: Apache (httpd) · Nginx · Tomcat · vsftpd
#  Fuentes  : WEB (dnf) o FTPS (repositorio privado)
# ============================================================

if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] Ejecuta como root: sudo bash main.sh"
    exit 1
fi

# ============================================================
# CONFIGURACION GLOBAL
# ============================================================

DOMAIN="reprobados.com"
CERT_DIR="/etc/ssl/reprobados"
CERT_FILE="$CERT_DIR/reprobados.crt"
KEY_FILE="$CERT_DIR/reprobados.key"

FTP_HOST=""
FTP_USER=""
FTP_PASS=""
FTP_PORT="990"
FTP_BASE="/http/Linux"
DOWNLOAD_DIR="/tmp/repo_ftp"

VERSION_ELEGIDA=""
PUERTO_ELEGIDO=""

mkdir -p "$DOWNLOAD_DIR"

# ============================================================
# HELPERS GENERALES
# ============================================================

servicio_instalado() {
    rpm -q "$1" &>/dev/null
}

abrir_firewall() {
    for p in "$@"; do
        firewall-cmd --permanent --add-port="$p" > /dev/null 2>&1
    done
    firewall-cmd --reload > /dev/null 2>&1
}

registrar_selinux_puerto() {
    local puerto="$1"
    if [[ "$puerto" != "80" && "$puerto" != "443" ]]; then
        semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null || true
    fi
}

read_puerto() {
    local default="$1"
    local puertos_reservados=(21 22 25 53 110 143 990 3306 5432 6379 27017 3389 445 139)

    while true; do
        read -rp "  Puerto para el servicio [default: $default]: " puerto
        puerto="${puerto:-$default}"

        if ! [[ "$puerto" =~ ^[0-9]+$ ]]; then
            echo "  Solo se permiten numeros."
            continue
        fi

        if [ "$puerto" -lt 1 ] || [ "$puerto" -gt 65535 ]; then
            echo "  Puerto fuera de rango (1-65535)."
            continue
        fi

        local reservado=false
        for r in "${puertos_reservados[@]}"; do
            if [ "$puerto" -eq "$r" ]; then
                echo "  El puerto $puerto esta reservado para otro servicio."
                reservado=true
                break
            fi
        done
        [ "$reservado" = true ] && continue

        if [ "$puerto" -lt 1024 ]; then
            echo "  [ADVERTENCIA] Puerto privilegiado (<1024). Se usara setcap si es necesario."
        fi

        PUERTO_ELEGIDO="$puerto"
        return 0
    done
}

# ============================================================
# SELECCION DE VERSION (desde dnf)
# ============================================================

get_versiones() {
    local paquete="$1"
    dnf list --showduplicates "$paquete" 2>/dev/null \
        | awk '/Available|Installed/{p=1;next} p{print $2}' \
        | sort -rV \
        | head -8
}

select_version() {
    local etiqueta="$1"
    shift
    local versiones=("$@")
    local total=${#versiones[@]}

    if [ "$total" -eq 0 ]; then
        echo "  [ERROR] No se encontraron versiones de $etiqueta."
        return 1
    fi

    local lts_idx=$((total / 2))

    echo ""
    echo "  Versiones disponibles de $etiqueta:"
    for ((i = 0; i < total; i++)); do
        local label=""
        [ $i -eq 0 ]                             && label="  (Latest)"
        [ $i -eq $lts_idx ] && [ $total -ge 3 ] && label="  (LTS / Estable)"
        [ $i -eq $((total - 1)) ]                && label="  (Oldest)"
        echo "    $((i + 1))) ${versiones[$i]}$label"
    done

    while true; do
        read -rp "  Version a instalar [1-$total]: " eleccion
        if [[ "$eleccion" =~ ^[0-9]+$ ]] && \
           [ "$eleccion" -ge 1 ] && [ "$eleccion" -le "$total" ]; then
            VERSION_ELEGIDA="${versiones[$((eleccion - 1))]}"
            return 0
        fi
        echo "  Opcion invalida."
    done
}

# ============================================================
# PAGINA INDEX.HTML (minimalista)
# ============================================================

new_index_html() {
    local servicio="$1"
    local version="$2"
    local puerto="$3"
    local webroot

    case "$servicio" in
        httpd)  webroot="/var/www/html" ;;
        nginx)  webroot="/var/www/html" ;;
        tomcat) webroot="/var/lib/tomcat/webapps/ROOT" ;;
        *)      webroot="/var/www/html" ;;
    esac

    mkdir -p "$webroot"
    cat > "$webroot/index.html" <<EOF
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>$servicio</title></head>
<body>
  <p>Servicio: $servicio</p>
  <p>Version: $version</p>
  <p>Puerto: $puerto</p>
</body>
</html>
EOF
    echo "  [OK] index.html generado en $webroot"
}

# ============================================================
# CLIENTE FTPS
# ============================================================

configurar_ftp_repo() {
    echo ""
    echo "=== Configuracion del repositorio FTPS privado ==="
    read -rp "  IP del servidor FTPS: " FTP_HOST
    read -rp "  Usuario FTPS: " FTP_USER
    read -rsp "  Contrasena FTPS: " FTP_PASS
    echo ""
    read -rp "  Puerto FTPS [990]: " _port
    FTP_PORT="${_port:-990}"
}

ftps_listar() {
    local ruta="$1"
    curl -s -l \
        --ssl-reqd --insecure \
        --user "$FTP_USER:$FTP_PASS" \
        "ftp://$FTP_HOST:$FTP_PORT$ruta/" 2>/dev/null \
    | grep -v '^\.' | grep -v '^$'
}

ftps_descargar() {
    local ruta_remota="$1"
    local destino="$2"

    echo "  Descargando: ftp://$FTP_HOST:$FTP_PORT$ruta_remota ..."
    curl -s --show-error \
        --ssl-reqd --insecure \
        --user "$FTP_USER:$FTP_PASS" \
        "ftp://$FTP_HOST:$FTP_PORT$ruta_remota" \
        -o "$destino"

    if [[ $? -eq 0 && -f "$destino" ]]; then
        echo "  [OK] Guardado en $destino"
        return 0
    else
        echo "  [ERROR] Fallo al descargar $ruta_remota"
        return 1
    fi
}

verificar_integridad() {
    local archivo="$1"
    local hash_file="${archivo}.sha256"

    if [[ ! -f "$hash_file" ]]; then
        echo "  [ERROR] No se encontro el archivo de hash: $hash_file"
        return 1
    fi

    echo "  Verificando integridad de $(basename "$archivo") ..."

    local hash_remoto hash_local
    hash_remoto=$(awk '{print $1}' "$hash_file")
    hash_local=$(sha256sum "$archivo" | awk '{print $1}')

    if [[ "$hash_local" == "$hash_remoto" ]]; then
        echo "  [OK] Integridad verificada."
        echo "       SHA256: $hash_local"
        return 0
    else
        echo "  [FAIL] Archivo CORRUPTO o modificado."
        echo "         Esperado : $hash_remoto"
        echo "         Calculado: $hash_local"
        return 1
    fi
}

instalar_desde_ftps() {
    local servicio_dir="$1"

    configurar_ftp_repo

    local ruta_svc="$FTP_BASE/$servicio_dir"

    echo ""
    echo "  Archivos disponibles en $ruta_svc:"
    mapfile -t archivos < <(ftps_listar "$ruta_svc" | grep -v '\.sha256$')

    if [[ ${#archivos[@]} -eq 0 ]]; then
        echo "  [ERROR] No hay archivos en $ruta_svc"
        echo "          Verifica IP, usuario, contrasena y estructura del repo."
        return 1
    fi

    for i in "${!archivos[@]}"; do
        echo "    $((i + 1))) ${archivos[$i]}"
    done

    local idx
    while true; do
        read -rp "  Selecciona el archivo [1-${#archivos[@]}]: " idx
        [[ "$idx" =~ ^[0-9]+$ ]] && \
        ((idx >= 1 && idx <= ${#archivos[@]})) && break
        echo "  Opcion invalida."
    done

    local archivo="${archivos[$((idx - 1))]}"
    local ruta_arch="$ruta_svc/$archivo"
    local dest_bin="$DOWNLOAD_DIR/$archivo"
    local dest_hash="$dest_bin.sha256"

    ftps_descargar "$ruta_arch" "$dest_bin"       || return 1
    ftps_descargar "${ruta_arch}.sha256" "$dest_hash" || \
        echo "  [ADVERTENCIA] No se encontro .sha256. Omitiendo verificacion."

    if [[ -f "$dest_hash" ]]; then
        verificar_integridad "$dest_bin" || {
            echo "  [ABORTANDO] Instalacion cancelada por fallo de integridad."
            return 1
        }
    fi

    echo ""
    echo "  Instalando $(basename "$dest_bin") ..."
    dnf install -y "$dest_bin" > /dev/null && \
        echo "  [OK] Instalacion completada." || \
        echo "  [ERROR] Fallo la instalacion del RPM."
}

# ============================================================
# CERTIFICADO SSL COMPARTIDO
# ============================================================

generar_certificado() {
    echo ""
    echo "  [SSL] Generando certificado autofirmado para $DOMAIN ..."
    mkdir -p "$CERT_DIR"

    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out    "$CERT_FILE" \
        -subj "/C=MX/ST=Sinaloa/L=LosMochis/O=Reprobados/CN=$DOMAIN" \
        2>/dev/null

    if [[ $? -eq 0 ]]; then
        echo "  [OK] Certificado: $CERT_FILE"
        echo "  [OK] Llave:       $KEY_FILE"
    else
        echo "  [ERROR] Fallo la generacion del certificado."
        return 1
    fi
}

# ============================================================
# SSL POR SERVICIO
# ============================================================

ssl_apache() {
    echo ""
    echo "  [SSL] Configurando SSL en Apache ..."

    dnf install -y mod_ssl > /dev/null

    sed -i '/^Listen /d' /etc/httpd/conf/httpd.conf

    cat > /etc/httpd/conf.d/reprobados-ssl.conf <<EOF
Listen 80
Listen 443

<VirtualHost *:80>
    ServerName $DOMAIN
    Redirect permanent / https://$DOMAIN/
</VirtualHost>

<VirtualHost *:443>
    ServerName $DOMAIN
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile    $CERT_FILE
    SSLCertificateKeyFile $KEY_FILE
    Header always set Strict-Transport-Security "max-age=31536000"
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

    chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true
    abrir_firewall 80/tcp 443/tcp
    systemctl restart httpd
    echo "  [OK] Apache SSL activo en puerto 443."
}

ssl_nginx() {
    echo ""
    echo "  [SSL] Configurando SSL en Nginx ..."

    sed -i 's/^\s*listen\s*80\s*default_server/    # listen 80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null
    sed -i 's/^\s*listen\s*\[::\]:80\s*default_server/    # listen [::]:80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null

    cat > /etc/nginx/conf.d/reprobados-ssl.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name $DOMAIN;
    root /var/www/html;
    ssl_certificate     $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location / { index index.html; }
}
EOF

    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true
    abrir_firewall 80/tcp 443/tcp
    systemctl restart nginx
    echo "  [OK] Nginx SSL activo en puerto 443."
}

ssl_tomcat() {
    echo ""
    echo "  [SSL] Configurando SSL en Tomcat ..."

    local p12="$CERT_DIR/reprobados.p12"
    local pass="reprobados123"

    openssl pkcs12 -export \
        -in "$CERT_FILE" -inkey "$KEY_FILE" \
        -out "$p12" -name reprobados \
        -passout pass:"$pass" 2>/dev/null

    local server_xml
    server_xml=$(find /etc/tomcat* -name "server.xml" 2>/dev/null | head -1)

    if [[ -z "$server_xml" ]]; then
        echo "  [ERROR] No se encontro server.xml de Tomcat."
        return 1
    fi

    cp "$server_xml" "${server_xml}.bak"

    if ! grep -q "Conector SSL Practica 7" "$server_xml"; then
        sed -i "s|</Service>|    <!-- Conector SSL Practica 7 -->
    <Connector port=\"8443\"
               protocol=\"org.apache.coyote.http11.Http11NioProtocol\"
               maxThreads=\"150\" SSLEnabled=\"true\">
        <SSLHostConfig>
            <Certificate certificateKeystoreFile=\"$p12\"
                         certificateKeystorePassword=\"$pass\"
                         type=\"RSA\" />
        </SSLHostConfig>
    </Connector>
</Service>|" "$server_xml"
    fi

    local tomcat_user
    tomcat_user=$(grep -E '^tomcat' /etc/passwd | cut -d: -f1 | head -n1)
    [[ -z "$tomcat_user" ]] && tomcat_user="tomcat"
    chown "$tomcat_user" "$p12" && chmod 640 "$p12"

    abrir_firewall 8443/tcp
    systemctl restart tomcat
    sleep 5

    systemctl is-active --quiet tomcat && \
        echo "  [OK] Tomcat SSL activo en puerto 8443." || \
        echo "  [ERROR] Tomcat no arranco. Revisa: journalctl -u tomcat"
}

ssl_vsftpd() {
    echo ""
    echo "  [SSL] Configurando FTPS en vsftpd ..."

    mkdir -p /etc/vsftpd/ssl

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/vsftpd/ssl/vsftpd.key \
        -out    /etc/vsftpd/ssl/vsftpd.crt \
        -subj "/C=MX/ST=Sinaloa/L=LosMochis/O=Reprobados/CN=$DOMAIN" \
        > /dev/null 2>&1
    chmod 600 /etc/vsftpd/ssl/vsftpd.key

    sed -i '/^ssl_enable/d;/^rsa_cert_file/d;/^rsa_private_key_file/d
            /^ssl_tlsv1/d;/^ssl_sslv2/d;/^ssl_sslv3/d
            /^force_local_data_ssl/d;/^force_local_logins_ssl/d
            /^require_ssl_reuse/d;/^ssl_ciphers/d
            /^implicit_ssl/d;/^listen_port/d' /etc/vsftpd/vsftpd.conf

    cat >> /etc/vsftpd/vsftpd.conf <<EOF

# SSL/TLS - Practica 7
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

    abrir_firewall 990/tcp 40000-50000/tcp
    setsebool -P ftpd_full_access 1 2>/dev/null || true
    systemctl restart vsftpd
    echo "  [OK] vsftpd FTPS activo en puerto 990."
}

# ============================================================
# VERIFICACION SSL
# ============================================================

verificar_ssl_servicio() {
    local servicio="$1"
    local puerto="$2"

    echo ""
    echo "  --- Verificando SSL: $servicio (puerto $puerto) ---"

    local resultado
    resultado=$(echo | openssl s_client \
        -connect "127.0.0.1:$puerto" \
        -servername "$DOMAIN" 2>/dev/null \
        | openssl x509 -noout -subject -dates 2>/dev/null)

    if [[ -n "$resultado" ]]; then
        echo "  [OK] $servicio responde con certificado SSL:"
        echo "$resultado" | sed 's/^/       /'
    else
        echo "  [FAIL] $servicio NO responde por SSL en puerto $puerto."
    fi
}

resumen_ssl() {
    echo ""
    echo "======================================================"
    echo "          RESUMEN DE VERIFICACION SSL/TLS             "
    echo "======================================================"

    local pass=0 fail=0

    _chk() {
        local nombre="$1" puerto="$2"
        if echo | openssl s_client -connect "127.0.0.1:$puerto" \
            -servername "$DOMAIN" 2>/dev/null \
            | openssl x509 -noout 2>/dev/null; then
            printf "  %-20s puerto %-6s  [OK]\n"   "$nombre" "$puerto"
            ((pass++))
        else
            printf "  %-20s puerto %-6s  [FAIL]\n" "$nombre" "$puerto"
            ((fail++))
        fi
    }

    systemctl is-active --quiet httpd  && _chk "Apache (httpd)" 443
    systemctl is-active --quiet nginx  && _chk "Nginx"          443
    systemctl is-active --quiet tomcat && _chk "Tomcat"         8443
    systemctl is-active --quiet vsftpd && _chk "vsftpd (FTPS)"  990

    echo "------------------------------------------------------"
    echo "  Exitosos: $pass   Fallidos: $fail"
    echo "======================================================"
}

# ============================================================
# INSTALAR APACHE
# ============================================================

instalar_apache() {
    echo ""
    echo "======================================================"
    echo "  INSTALACION: Apache (httpd)"
    echo "======================================================"

    # 1. Origen
    echo "  Origen:"
    echo "    1) WEB  - dnf"
    echo "    2) FTPS - repositorio privado"
    read -rp "  Elige [1/2]: " origen

    case "$origen" in
    1)
        mapfile -t versiones < <(get_versiones "httpd")
        select_version "httpd" "${versiones[@]}" || return 1
        echo ""
        echo "  Instalando httpd $VERSION_ELEGIDA ..."
        if ! dnf install -y "httpd-$VERSION_ELEGIDA" > /dev/null 2>&1; then
            echo "  [ADVERTENCIA] Version exacta no disponible, instalando la actual..."
            dnf install -y httpd > /dev/null
        fi
        ;;
    2)
        instalar_desde_ftps "Apache" || return 1
        ;;
    *)
        echo "  Opcion invalida."; return 1 ;;
    esac

    # 2. Puerto
    read_puerto 80

    # 3. SSL
    read -rp "  Activar SSL en Apache? [S/N]: " activar_ssl

    # 4. Configurar
    sed -i '/^Listen /d' /etc/httpd/conf/httpd.conf

    local version_real
    version_real=$(rpm -q httpd --queryformat "%{VERSION}-%{RELEASE}" 2>/dev/null)

    if [[ "${activar_ssl,,}" == "s" ]]; then
        [[ ! -f "$CERT_FILE" ]] && generar_certificado
        new_index_html "httpd" "$version_real" "443"
        chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true
        ssl_apache
    else
        new_index_html "httpd" "$version_real" "$PUERTO_ELEGIDO"
        chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true
        cat > /etc/httpd/conf.d/reprobados.conf <<EOF
Listen $PUERTO_ELEGIDO

<VirtualHost *:$PUERTO_ELEGIDO>
    ServerName $DOMAIN
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
        abrir_firewall "$PUERTO_ELEGIDO/tcp"
        systemctl enable --now httpd
        systemctl restart httpd
    fi

    echo ""
    echo "[OK] Apache activo. Version: $version_real"
    systemctl is-active --quiet httpd && \
        echo "     Estado: CORRIENDO" || echo "     Estado: FALLO"
    [[ "${activar_ssl,,}" == "s" ]] && verificar_ssl_servicio "Apache" 443
}

# ============================================================
# INSTALAR NGINX
# ============================================================

instalar_nginx() {
    echo ""
    echo "======================================================"
    echo "  INSTALACION: Nginx"
    echo "======================================================"

    # 1. Origen
    echo "  Origen:"
    echo "    1) WEB  - dnf"
    echo "    2) FTPS - repositorio privado"
    read -rp "  Elige [1/2]: " origen

    case "$origen" in
    1)
        mapfile -t versiones < <(get_versiones "nginx")
        select_version "nginx" "${versiones[@]}" || return 1
        echo ""
        echo "  Instalando nginx $VERSION_ELEGIDA ..."
        if ! dnf install -y "nginx-$VERSION_ELEGIDA" > /dev/null 2>&1; then
            echo "  [ADVERTENCIA] Version exacta no disponible, instalando la actual..."
            dnf install -y nginx > /dev/null
        fi
        ;;
    2)
        instalar_desde_ftps "Nginx" || return 1
        ;;
    *)
        echo "  Opcion invalida."; return 1 ;;
    esac

    # 2. Puerto
    read_puerto 8080

    # 3. SSL
    read -rp "  Activar SSL en Nginx? [S/N]: " activar_ssl

    # 4. Configurar
    sed -i 's/^\s*listen\s*80\s*default_server/    # listen 80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null
    sed -i 's/^\s*listen\s*\[::\]:80\s*default_server/    # listen [::]:80 default_server/' \
        /etc/nginx/nginx.conf 2>/dev/null

    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    chcon -R --type=httpd_sys_content_t /var/www/html 2>/dev/null || true

    local version_real
    version_real=$(rpm -q nginx --queryformat "%{VERSION}-%{RELEASE}" 2>/dev/null)

    if [[ "${activar_ssl,,}" == "s" ]]; then
        [[ ! -f "$CERT_FILE" ]] && generar_certificado
        new_index_html "nginx" "$version_real" "443"
        ssl_nginx
    else
        registrar_selinux_puerto "$PUERTO_ELEGIDO"
        new_index_html "nginx" "$version_real" "$PUERTO_ELEGIDO"
        cat > /etc/nginx/conf.d/reprobados.conf <<EOF
server {
    listen $PUERTO_ELEGIDO;
    server_name $DOMAIN;
    root /var/www/html;
    index index.html;
}
EOF
        abrir_firewall "$PUERTO_ELEGIDO/tcp"
        systemctl enable --now nginx
        systemctl restart nginx
    fi

    echo ""
    echo "[OK] Nginx activo. Version: $version_real"
    systemctl is-active --quiet nginx && \
        echo "     Estado: CORRIENDO" || echo "     Estado: FALLO"
    [[ "${activar_ssl,,}" == "s" ]] && verificar_ssl_servicio "Nginx" 443
}

# ============================================================
# INSTALAR TOMCAT
# ============================================================

instalar_tomcat() {
    echo ""
    echo "======================================================"
    echo "  INSTALACION: Tomcat"
    echo "======================================================"

    # 1. Origen
    echo "  Origen:"
    echo "    1) WEB  - dnf"
    echo "    2) FTPS - repositorio privado"
    read -rp "  Elige [1/2]: " origen

    case "$origen" in
    1)
        mapfile -t versiones < <(get_versiones "tomcat")
        select_version "tomcat" "${versiones[@]}" || return 1
        dnf install -y java-latest-openjdk > /dev/null
        echo ""
        echo "  Instalando tomcat $VERSION_ELEGIDA ..."
        if ! dnf install -y "tomcat-$VERSION_ELEGIDA" > /dev/null 2>&1; then
            echo "  [ADVERTENCIA] Version exacta no disponible, instalando la actual..."
            dnf install -y tomcat > /dev/null
        fi
        ;;
    2)
        instalar_desde_ftps "Tomcat" || return 1
        dnf install -y java-latest-openjdk > /dev/null
        ;;
    *)
        echo "  Opcion invalida."; return 1 ;;
    esac

    # 2. Puerto
    read_puerto 8090

    # 3. SSL
    read -rp "  Activar SSL en Tomcat? [S/N]: " activar_ssl

    # 4. Configurar
    local T_USER
    T_USER=$(grep -E '^tomcat' /etc/passwd | cut -d: -f1 | head -n1)
    [[ -z "$T_USER" ]] && T_USER="tomcat"

    if [ "$PUERTO_ELEGIDO" -lt 1024 ]; then
        local JAVA_BIN
        JAVA_BIN=$(readlink -f "$(which java)")
        setcap 'cap_net_bind_service=+ep' "$JAVA_BIN"
    fi

    local version_real
    version_real=$(rpm -q tomcat --queryformat "%{VERSION}-%{RELEASE}" 2>/dev/null)

    if [[ "${activar_ssl,,}" == "s" ]]; then
        [[ ! -f "$CERT_FILE" ]] && generar_certificado
        new_index_html "tomcat" "$version_real" "8443"
        mkdir -p /var/lib/tomcat/webapps/ROOT
        cp /var/www/html/index.html /var/lib/tomcat/webapps/ROOT/index.html
        chown -R "$T_USER:$T_USER" /var/lib/tomcat/webapps/ROOT
        # Configurar conector HTTP base antes del SSL
        cat > /etc/tomcat/server.xml <<XML
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$PUERTO_ELEGIDO" protocol="HTTP/1.1" connectionTimeout="20000"/>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>
XML
        abrir_firewall "$PUERTO_ELEGIDO/tcp"
        systemctl enable --now tomcat
        systemctl restart tomcat
        sleep 5
        ssl_tomcat
    else
        new_index_html "tomcat" "$version_real" "$PUERTO_ELEGIDO"
        mkdir -p /var/lib/tomcat/webapps/ROOT
        cp /var/www/html/index.html /var/lib/tomcat/webapps/ROOT/index.html
        chown -R "$T_USER:$T_USER" /var/lib/tomcat/webapps/ROOT
        cat > /etc/tomcat/server.xml <<XML
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="$PUERTO_ELEGIDO" protocol="HTTP/1.1" connectionTimeout="20000"/>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true"/>
    </Engine>
  </Service>
</Server>
XML
        abrir_firewall "$PUERTO_ELEGIDO/tcp"
        systemctl enable --now tomcat
        systemctl restart tomcat
        sleep 8
    fi

    echo ""
    echo "[OK] Tomcat activo. Version: $version_real"
    systemctl is-active --quiet tomcat && \
        echo "     Estado: CORRIENDO" || echo "     Estado: FALLO"
    [[ "${activar_ssl,,}" == "s" ]] && verificar_ssl_servicio "Tomcat" 8443
}

# ============================================================
# INSTALAR VSFTPD
# ============================================================

instalar_vsftpd() {
    echo ""
    echo "======================================================"
    echo "  CONFIGURACION: vsftpd"
    echo "======================================================"

    # 1. Origen
    echo "  Origen:"
    echo "    1) WEB  - dnf"
    echo "    2) FTPS - repositorio privado"
    read -rp "  Elige [1/2]: " origen

    case "$origen" in
    1)
        if servicio_instalado vsftpd; then
            echo "  vsftpd ya esta instalado."
        else
            dnf install -y vsftpd openssl > /dev/null
        fi
        ;;
    2)
        instalar_desde_ftps "vsftpd" || return 1
        ;;
    *)
        echo "  Opcion invalida."; return 1 ;;
    esac

    # 2. SSL
    read -rp "  Activar FTPS (SSL) en vsftpd? [S/N]: " activar_ssl

    # 3. Configurar base
    grep -q "/bin/bash" /etc/shells || echo "/bin/bash" >> /etc/shells

    mkdir -p /srv/ftp/{anon,autenticados,grupos/general,grupos/reprobados,grupos/recursadores}
    chmod 755 /srv/ftp/autenticados
    chown root:root /srv/ftp/autenticados

    cat > /etc/vsftpd/vsftpd.conf <<EOF
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
anonymous_enable=YES
anon_root=/srv/ftp/anon
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
user_sub_token=\$USER
chroot_local_user=YES
allow_writeable_chroot=YES
local_root=/srv/ftp/autenticados/\$USER
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000
EOF

    setsebool -P ftpd_full_access 1 2>/dev/null || true
    systemctl enable --now vsftpd

    if [[ "${activar_ssl,,}" == "s" ]]; then
        ssl_vsftpd
    else
        abrir_firewall 20/tcp 21/tcp 40000-50000/tcp
        systemctl restart vsftpd
    fi

    local version_real
    version_real=$(rpm -q vsftpd --queryformat "%{VERSION}-%{RELEASE}" 2>/dev/null)

    echo ""
    echo "[OK] vsftpd activo. Version: $version_real"
    systemctl is-active --quiet vsftpd && \
        echo "     Estado: CORRIENDO" || echo "     Estado: FALLO"
    [[ "${activar_ssl,,}" == "s" ]] && verificar_ssl_servicio "vsftpd FTPS" 990
}

# ============================================================
# MENU PRINCIPAL
# ============================================================

while true; do
    echo ""
    echo "======================================================"
    echo "   PRACTICA 7 - Orquestador Linux  [$DOMAIN]"
    echo "======================================================"
    echo "  1) Apache (httpd)"
    echo "  2) Nginx"
    echo "  3) Tomcat"
    echo "  4) vsftpd (FTP)"
    echo "  5) Resumen SSL (todos los servicios)"
    echo "  0) Salir"
    echo "------------------------------------------------------"
    read -rp "  Opcion: " opc

    case "$opc" in
        1) instalar_apache  ;;
        2) instalar_nginx   ;;
        3) instalar_tomcat  ;;
        4) instalar_vsftpd  ;;
        5) resumen_ssl      ;;
        0) echo "  Saliendo..."; break ;;
        *) echo "  Opcion invalida." ;;
    esac
done
