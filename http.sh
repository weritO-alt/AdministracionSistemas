#!/bin/bash
instalar_dependencias_base() {
    echo "Instalando dependencias base..."
    if ! dnf install -y curl net-tools firewalld psmisc iproute; then
        echo "  Advertencia: Algunas dependencias base no se instalaron correctamente." >&2
    fi
    systemctl enable firewalld --now 2>/dev/null
}
liberar_entorno() {
    echo "Iniciando limpieza profunda del entorno..."
    echo "Deteniendo servicios conocidos..."
    systemctl stop httpd nginx tomcat 2>/dev/null
    echo "Liberando procesos de servidores web..."
    local procesos=("httpd" "nginx" "java")
    for proc in "${procesos[@]}"; do
        pids=$(pgrep -f "$proc")
        [ -n "$pids" ] && kill -9 $pids 2>/dev/null
    done
    echo "Eliminando paquetes..."
    dnf remove -y httpd\* nginx\* tomcat\* 2>/dev/null
    dnf autoremove -y 2>/dev/null
    rm -rf /var/www/html/* /var/www/httpd_* /var/www/nginx_* 2>/dev/null
    rm -rf /usr/share/tomcat/webapps/ROOT/* 2>/dev/null
    echo "Entorno 100% liberado y limpio!"
}
solicitarPuerto() {
    local puerto
    declare -A servicios=(
        [20]="FTP" [21]="FTP" [22]="SSH" [25]="SMTP" [53]="DNS"
        [110]="POP3" [143]="IMAP" [445]="SMB/Samba" [2222]="SSH alternativo"
        [3306]="MySQL/MariaDB" [5432]="PostgreSQL" [3389]="RDP"
    )
    local reservedPorts=(1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 \
        77 79 110 111 113 115 117 118 119 123 135 137 139 143 161 177 179 \
        389 427 445 465 512 513 514 515 526 530 531 532 540 548 554 556 \
        563 587 601 636 989 990 993 995 1723 2049 2222 3306 3389 5432)
    while true; do
        read -p "  Ingrese el puerto (ej. 80, 8080, 8888): " puerto
        if [[ ! "$puerto" =~ ^[0-9]+$ ]] || [ "$puerto" -le 0 ] || [ "$puerto" -gt 65535 ]; then
            echo "  Error: Ingresa un numero de puerto valido (1-65535)." >&2; continue
        fi
        if [[ " ${reservedPorts[*]} " =~ " ${puerto} " ]]; then
            local desc=${servicios[$puerto]:-"Sistema Critico"}
            echo "  Error: Puerto $puerto reservado para $desc. Elige otro." >&2; continue
        fi
        if ss -tuln | grep -q ":$puerto "; then
            echo "  Error: El puerto $puerto ya esta ocupado por otro servicio." >&2; continue
        fi
        break
    done
    echo "$puerto"
}
seleccionar_version() {
    local paquete=$1
    [ "$paquete" == "apache" ] && paquete="httpd"
    mapfile -t versiones_crudas < <(
        dnf repoquery "$paquete" --available --queryformat "%{version}-%{release}" 2>/dev/null \
        | sort -Vu | tail -n 5
    )
    if [ ${#versiones_crudas[@]} -eq 0 ]; then
        mapfile -t versiones_crudas < <(
            dnf info "$paquete" 2>/dev/null \
            | awk '/^Version|^Release/{print $3}' \
            | paste - - | awk '{print $1"-"$2}' | head -3
        )
    fi
    if [ ${#versiones_crudas[@]} -eq 0 ]; then
        echo "  No se encontraron versiones para $paquete." >&2; return 1
    fi
    if [ ${#versiones_crudas[@]} -eq 1 ]; then
        echo "" >&2
        echo "  Solo hay una version disponible para $paquete: ${versiones_crudas[0]}" >&2
        echo "  Se usara automaticamente." >&2
        echo "" >&2
        echo "${versiones_crudas[0]}"
        return
    fi
    echo "" >&2
    echo "  Versiones disponibles para $paquete:" >&2
    local i=1
    for ver in "${versiones_crudas[@]}"; do
        if [[ "$ver" == *"fc"* ]]; then
            echo "    $i) $ver  --> [Version Repositorio Fedora]" >&2
        else
            echo "    $i) $ver  --> [Version Disponible]" >&2
        fi
        ((i++))
    done
    echo "" >&2
    while true; do
        read -p "  Selecciona el numero de version (1-${#versiones_crudas[@]}): " seleccion
        if [[ "$seleccion" =~ ^[0-9]+$ ]] && [ "$seleccion" -ge 1 ] && [ "$seleccion" -le "${#versiones_crudas[@]}" ]; then
            echo "${versiones_crudas[$((seleccion - 1))]}"; break
        else
            echo "  Error: Seleccion invalida." >&2
        fi
    done
}
configurar_firewall() {
    local puerto=$1
    echo "  Configurando firewalld: abriendo puerto $puerto, cerrando HTTP no usados..."
    firewall-cmd --permanent --add-port="$puerto"/tcp > /dev/null 2>&1
    for p in 80 443 8080 8888; do
        if [ "$p" -ne "$puerto" ]; then
            firewall-cmd --permanent --remove-port="$p"/tcp > /dev/null 2>&1
            firewall-cmd --permanent --remove-service=http  > /dev/null 2>&1
            firewall-cmd --permanent --remove-service=https > /dev/null 2>&1
        fi
    done
    firewall-cmd --reload > /dev/null 2>&1
    echo "  Firewalld configurado. Solo el puerto $puerto habilitado para HTTP."
}
crear_index() {
    local ruta=$1 servicio=$2 version=$3 puerto=$4
    local ip
    ip=$(hostname -I | awk '{print $1}')
    cat <<HTMLEOF > "$ruta/index.html"
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>$servicio</title></head>
<body>
  <h2>$servicio</h2>
  <p>Version: $version</p>
  <p>IP: $ip</p>
  <p>Puerto: $puerto</p>
</body>
</html>
HTMLEOF
}
crear_usuario_dedicado() {
    local usuario=$1 directorio=$2
    if ! id "$usuario" &>/dev/null; then
        useradd --system --no-create-home --shell /sbin/nologin "$usuario"
        echo "  Usuario dedicado '$usuario' creado."
    fi
    chown -R "$usuario":"$usuario" "$directorio"
    chmod -R 750 "$directorio"
    echo "  Permisos limitados a $directorio para el usuario $usuario."
}
aplicar_security_headers_apache() {
    echo "  Aplicando Hardening en Apache (httpd)..."
    cat <<'EOF' > /etc/httpd/conf.d/security.conf
# Ocultar version del servidor
ServerTokens Prod
ServerSignature Off

# Security Headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "no-referrer-when-downgrade"
    Header always unset X-Powered-By
</IfModule>

# Bloquear metodos HTTP peligrosos
<Directory "/">
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>
EOF
    echo "  Security Headers configurados en Apache."
}
aplicar_security_headers_nginx() {
    echo "  Aplicando Hardening en Nginx..."
    mkdir -p /etc/nginx/conf.d
    cat <<'EOF' > /etc/nginx/conf.d/security-headers.conf
server_tokens off;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
EOF
    echo "  Security Headers configurados en Nginx."
}
aplicar_security_headers_tomcat() {
    local webxml="/etc/tomcat/web.xml"
    echo "  Aplicando Hardening en Tomcat..."
    sed -i 's/<Connector/<Connector server="WebServer"/g' /etc/tomcat/server.xml 2>/dev/null
    if [ -f "$webxml" ] && ! grep -q "HttpHeaderSecurityFilter" "$webxml"; then
        sed -i '/<\/web-app>/i\
    <filter><filter-name>httpHeaderSecurity<\/filter-name>\
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter<\/filter-class>\
    <init-param><param-name>antiClickJackingEnabled<\/param-name><param-value>true<\/param-value><\/init-param>\
    <init-param><param-name>antiClickJackingOption<\/param-name><param-value>SAMEORIGIN<\/param-value><\/init-param>\
    <init-param><param-name>blockContentTypeSniffingEnabled<\/param-name><param-value>true<\/param-value><\/init-param>\
    <init-param><param-name>xssProtectionEnabled<\/param-name><param-value>true<\/param-value><\/init-param>\
    <\/filter>\
    <filter-mapping><filter-name>httpHeaderSecurity<\/filter-name>\
    <url-pattern>\/*<\/url-pattern><\/filter-mapping>' "$webxml" 2>/dev/null
    fi
    echo "  Security Headers configurados en Tomcat."
}
instalar_apache() {
    local version=$1 puerto=$2
    echo ""; echo "  Instalando Apache (httpd) en puerto $puerto..."
    if ! dnf install -y httpd; then
        echo "  Error: No se pudo instalar httpd." >&2; return 1
    fi
    if ! rpm -q httpd > /dev/null 2>&1; then
        echo "  Error: httpd no quedo instalado correctamente." >&2; return 1
    fi
    local vhost_dir="/var/www/httpd_$puerto"
    mkdir -p "$vhost_dir"
    # Limpiar configuracion previa de puerto en httpd.conf
    sed -i "s/^Listen .*/Listen $puerto/" /etc/httpd/conf/httpd.conf
    sed -i "s/^Listen 443/#Listen 443/" /etc/httpd/conf/httpd.conf 2>/dev/null
    cat <<EOF > /etc/httpd/conf.d/vhost.conf
<VirtualHost *:$puerto>
    ServerAdmin webmaster@localhost
    DocumentRoot $vhost_dir
    ErrorLog /var/log/httpd/error.log
    CustomLog /var/log/httpd/access.log combined
</VirtualHost>
EOF
    aplicar_security_headers_apache
    crear_index "$vhost_dir" "Apache (httpd)" "$version" "$puerto"
    crear_usuario_dedicado "apache" "$vhost_dir"
    if command -v semanage &>/dev/null; then
        semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
    fi
    configurar_firewall "$puerto"
    systemctl enable httpd --now
    if ! systemctl restart httpd; then
        echo "  Error al iniciar httpd. Revisa: journalctl -xe -u httpd" >&2; return 1
    fi
    echo ""; echo "  [OK] Apache (httpd) instalado y asegurado."
    echo "       Ruta web : $vhost_dir"
    echo "       Verificar: curl -I http://localhost:$puerto"
}
instalar_nginx() {
    local version=$1 puerto=$2
    echo ""; echo "  Instalando Nginx en puerto $puerto..."
    if ! dnf install -y nginx; then
        echo "  Error: No se pudo instalar nginx." >&2; return 1
    fi
    if ! rpm -q nginx > /dev/null 2>&1; then
        echo "  Error: nginx no quedo instalado correctamente." >&2; return 1
    fi
    local vhost_dir="/var/www/nginx_$puerto"
    mkdir -p "$vhost_dir"
    mkdir -p /etc/nginx/conf.d

    # Deshabilitar el server block por defecto en nginx.conf
    sed -i '/^\s*server\s*{/,/^\s*}/{ s/^/#DISABLED# / }' /etc/nginx/nginx.conf 2>/dev/null

    # Aplicar headers de seguridad en archivo separado (sin bloques server{})
    aplicar_security_headers_nginx

    # Crear vhost con includes del archivo de headers
    cat <<EOF > /etc/nginx/conf.d/vhost_$puerto.conf
server {
    listen $puerto;
    root $vhost_dir;
    index index.html;
    server_name _;

    server_tokens off;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    if (\$request_method !~ ^(GET|POST|HEAD)$) {
        return 405;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    crear_index "$vhost_dir" "Nginx" "$version" "$puerto"
    crear_usuario_dedicado "nginx" "$vhost_dir"
    if command -v semanage &>/dev/null; then
        semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
    fi
    configurar_firewall "$puerto"
    systemctl enable nginx --now
    if ! systemctl restart nginx; then
        echo "  Error al iniciar nginx. Revisa: journalctl -xe -u nginx" >&2
        nginx -t 2>&1
        return 1
    fi
    echo ""; echo "  [OK] Nginx instalado y asegurado."
    echo "       Ruta web : $vhost_dir"
    echo "       Verificar: curl -I http://localhost:$puerto"
}
instalar_tomcat() {
    local version=$1 puerto=$2
    echo ""; echo "  Instalando Tomcat en puerto $puerto..."
    # Detectar paquete java disponible
    local java_pkg
    if dnf list available java-21-openjdk-headless &>/dev/null 2>&1; then
        java_pkg="java-21-openjdk-headless"
    elif dnf list available java-17-openjdk-headless &>/dev/null 2>&1; then
        java_pkg="java-17-openjdk-headless"
    else
        java_pkg=$(dnf repoquery "java-*-openjdk-headless" --available --queryformat "%{name}" 2>/dev/null | sort -V | tail -1)
    fi
    echo "  Usando Java: ${java_pkg:-java-openjdk}"
    if ! dnf install -y tomcat tomcat-webapps ${java_pkg:-java-latest-openjdk-headless}; then
        echo "  Error: No se pudo instalar Tomcat." >&2; return 1
    fi
    if ! rpm -q tomcat > /dev/null 2>&1; then
        echo "  Error: tomcat no quedo instalado correctamente." >&2; return 1
    fi
    sed -i "s/port=\"8080\"/port=\"$puerto\"/g" /etc/tomcat/server.xml
    aplicar_security_headers_tomcat
    mkdir -p /usr/share/tomcat/webapps/ROOT
    crear_index "/usr/share/tomcat/webapps/ROOT" "Tomcat" "$version" "$puerto"
    crear_usuario_dedicado "tomcat" "/usr/share/tomcat/webapps"
    if command -v semanage &>/dev/null; then
        semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
    fi
    configurar_firewall "$puerto"
    systemctl enable tomcat --now
    if ! systemctl restart tomcat; then
        echo "  Error al iniciar tomcat. Revisa: journalctl -xe -u tomcat" >&2; return 1
    fi
    echo ""; echo "  [OK] Tomcat instalado y asegurado."
    echo "       Verificar: curl -I http://localhost:$puerto"
}
verificar_servicio() {
    local servicio=$1 puerto=$2
    echo ""
    echo "  +------ Verificacion: $servicio en puerto $puerto ------+"
    if systemctl is-active --quiet "$servicio" 2>/dev/null; then
        echo "  [OK] Servicio $servicio : ACTIVO"
    else
        echo "  [!!] Servicio $servicio : INACTIVO"
        echo "       Revisa: journalctl -xe -u $servicio"
    fi
    if ss -tuln | grep -q ":$puerto "; then
        echo "  [OK] Puerto $puerto     : ESCUCHANDO"
    else
        echo "  [??] Puerto $puerto     : No detectado aun"
    fi
    echo "  [>>] Encabezados HTTP (curl -I http://localhost:$puerto):"
    curl -sI "http://localhost:$puerto" 2>/dev/null \
        | grep -E "^HTTP|^Server:|^X-Frame|^X-Content|^X-XSS" \
        | sed 's/^/       /' \
        || echo "       (Servicio aun iniciando, reintenta en unos segundos)"
    echo "  +---------------------------------------------------+"
}
desinstalar_servidor() {
    echo ""; echo "  ============================================"
    echo "    Desinstalar servidor especifico"
    echo "  ============================================"
    echo "  1) Apache (httpd)   2) Nginx   3) Tomcat"; echo ""
    local svc_op
    read -p "  Selecciona el servidor (1-3): " svc_op
    local pkg servicio
    case "$svc_op" in
        1) pkg="httpd";  servicio="httpd" ;;
        2) pkg="nginx";  servicio="nginx" ;;
        3) pkg="tomcat"; servicio="tomcat" ;;
        *) echo "  Opcion invalida." >&2; return ;;
    esac
    if ! rpm -q "$pkg" > /dev/null 2>&1; then
        echo "  El servidor '$pkg' no esta instalado actualmente."; return
    fi
    echo ""
    read -p "  Confirmar desinstalacion de $pkg? [s/N]: " conf
    [[ ! "$conf" =~ ^[sS]$ ]] && { echo "  Cancelado."; return; }
    echo "  Deteniendo $servicio..."
    systemctl stop "$servicio" 2>/dev/null
    pkill -f "$pkg" 2>/dev/null
    echo "  Desinstalando $pkg..."
    dnf remove -y "$pkg"\* 2>/dev/null
    dnf autoremove -y 2>/dev/null
    rm -rf /var/www/"${pkg}"_* /var/www/httpd_* 2>/dev/null
    echo "  [OK] $pkg desinstalado correctamente."
}
cambiar_version() {
    echo ""; echo "  ============================================"
    echo "    Cambiar version de servidor"
    echo "  ============================================"
    echo "  1) Apache (httpd)   2) Nginx   3) Tomcat"; echo ""
    local svc_op
    read -p "  Selecciona el servidor (1-3): " svc_op
    local pkg servicio nombre
    case "$svc_op" in
        1) pkg="httpd";  servicio="httpd";  nombre="Apache (httpd)" ;;
        2) pkg="nginx";  servicio="nginx";  nombre="Nginx" ;;
        3) pkg="tomcat"; servicio="tomcat"; nombre="Tomcat" ;;
        *) echo "  Opcion invalida." >&2; return ;;
    esac
    local version_actual
    version_actual=$(rpm -q "$pkg" --queryformat "%{version}-%{release}" 2>/dev/null)
    if [ -z "$version_actual" ]; then
        echo "  $nombre no esta instalado. Usa la opcion Instalar primero."; return
    fi
    echo "  Version actual instalada: $version_actual"; echo ""
    local nueva_version
    nueva_version=$(seleccionar_version "$pkg")
    [ $? -ne 0 ] || [ -z "$nueva_version" ] && return
    if [ "$nueva_version" == "$version_actual" ]; then
        echo "  La version seleccionada ya esta instalada."; return
    fi
    echo "  Nueva version: $nueva_version"; echo ""
    local puerto
    puerto=$(solicitarPuerto)
    echo "  Puerto: $puerto"; echo ""
    read -p "  Confirmar cambio de $version_actual a $nueva_version en puerto $puerto? [s/N]: " conf
    [[ ! "$conf" =~ ^[sS]$ ]] && { echo "  Cancelado."; return; }
    echo "  Desinstalando version anterior..."
    systemctl stop "$servicio" 2>/dev/null
    dnf remove -y "$pkg"\* 2>/dev/null
    dnf autoremove -y 2>/dev/null
    rm -rf /var/www/"${pkg}"_* /var/www/httpd_* 2>/dev/null
    echo "  Instalando nueva version..."
    case "$servicio" in
        httpd)  instalar_apache "$nueva_version" "$puerto"; verificar_servicio "httpd"  "$puerto" ;;
        nginx)  instalar_nginx  "$nueva_version" "$puerto"; verificar_servicio "nginx"  "$puerto" ;;
        tomcat) instalar_tomcat "$nueva_version" "$puerto"; verificar_servicio "tomcat" "$puerto" ;;
    esac
}
mostrar_banner() {
    clear; echo ""
    echo "  +======================================================+"
    echo "  |      SISTEMA DE APROVISIONAMIENTO WEB - FEDORA      |"
    echo "  |           Practica 6 | Bash Automatizado             |"
    echo "  +======================================================+"
    printf  "  |  Sistema : %-42s|\n" "$(uname -sr)"
    printf  "  |  Distro  : %-42s|\n" "$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')"
    printf  "  |  Fecha   : %-42s|\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    echo "  +======================================================+"; echo ""
}
menu_principal() {
    echo "  +-----------------------------------------+"
    echo "  |        SELECCIONA UNA OPCION             |"
    echo "  +-----------------------------------------+"
    echo "  |  1) Instalar Apache (httpd)              |"
    echo "  |  2) Instalar Nginx                       |"
    echo "  |  3) Instalar Tomcat                      |"
    echo "  |  4) Verificar servicio activo            |"
    echo "  |  5) Desinstalar servidor especifico      |"
    echo "  |  6) Cambiar version de servidor          |"
    echo "  |  7) Limpiar entorno (purgar todo)        |"
    echo "  |  8) Levantar/Reiniciar servicio          |"
    echo "  |  0) Salir                                |"
    echo "  +-----------------------------------------+"; echo ""
}
leer_opcion() {
    local opcion
    while true; do
        read -p "  Opcion: " opcion
        [[ "$opcion" =~ ^[0-8]$ ]] && { echo "$opcion"; return; }
        echo "  Error: Opcion invalida. Ingresa un numero del 0 al 7." >&2
    done
}
flujo_instalacion() {
    local servicio=$1 nombre=$2
    echo ""; echo "  ============================================"
    echo "    Instalacion de $nombre"
    echo "  ============================================"
    instalar_dependencias_base
    local pkg="$servicio"
    [ "$servicio" == "apache" ] && pkg="httpd"
    if rpm -q "$pkg" > /dev/null 2>&1; then
        local version_actual
        version_actual=$(rpm -q "$pkg" --queryformat "%{version}-%{release}")
        echo "  $nombre ya esta instalado (version: $version_actual)."
        echo ""
        echo "  1) Reinstalar con otra version"
        echo "  2) Cancelar"
        echo ""
        local op
        read -p "  Opcion: " op
        if [ "$op" == "1" ]; then
            cambiar_version; return
        else
            echo "  Cancelado."; return
        fi
    fi
    local version
    version=$(seleccionar_version "$servicio")
    [ $? -ne 0 ] || [ -z "$version" ] && { echo "  No se pudo obtener version. Abortando." >&2; return 1; }
    echo "  Version seleccionada: $version"; echo ""
    local puerto
    puerto=$(solicitarPuerto)
    echo "  Puerto seleccionado : $puerto"; echo ""
    read -p "  Confirmar instalacion de $nombre en puerto $puerto? [s/N]: " confirmacion
    [[ ! "$confirmacion" =~ ^[sS]$ ]] && { echo "  Instalacion cancelada."; return 0; }
    case "$servicio" in
        apache) instalar_apache "$version" "$puerto"; verificar_servicio "httpd"  "$puerto" ;;
        nginx)  instalar_nginx  "$version" "$puerto"; verificar_servicio "nginx"  "$puerto" ;;
        tomcat) instalar_tomcat "$version" "$puerto"; verificar_servicio "tomcat" "$puerto" ;;
    esac
}
levantar_servicio() {
    echo ""; echo "  ============================================"
    echo "    Levantar / Reiniciar servicio"
    echo "  ============================================"
    local instalados=()
    rpm -q httpd  > /dev/null 2>&1 && instalados+=("1) Apache (httpd)")
    rpm -q nginx  > /dev/null 2>&1 && instalados+=("2) Nginx")
    rpm -q tomcat > /dev/null 2>&1 && instalados+=("3) Tomcat")
    if [ ${#instalados[@]} -eq 0 ]; then
        echo "  No hay ningun servidor instalado."; return
    fi
    echo "  Servicios instalados:"; echo ""
    for s in "${instalados[@]}"; do echo "    $s"; done
    echo ""
    local svc_op
    read -p "  Selecciona el servicio (1-3): " svc_op
    local servicio nombre
    case "$svc_op" in
        1) servicio="httpd";  nombre="Apache (httpd)" ;;
        2) servicio="nginx";  nombre="Nginx" ;;
        3) servicio="tomcat"; nombre="Tomcat" ;;
        *) echo "  Opcion invalida." >&2; return ;;
    esac
    local puerto
    read -p "  Ingresa el puerto en el que corre $nombre: " puerto
    [[ ! "$puerto" =~ ^[0-9]+$ ]] && { echo "  Puerto invalido." >&2; return; }
    echo ""
    echo "  Actualizando configuracion de $nombre al puerto $puerto..."
    case "$servicio" in
        httpd)
            sed -i "s/^Listen .*/Listen $puerto/" /etc/httpd/conf/httpd.conf
            sed -i "s/VirtualHost \*:[0-9]*/VirtualHost *:$puerto/" /etc/httpd/conf.d/vhost.conf 2>/dev/null
            if command -v semanage &>/dev/null; then
                semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null ||                 semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
            fi
            ;;
        nginx)
            local vhost_file
            vhost_file=$(ls /etc/nginx/conf.d/vhost_*.conf 2>/dev/null | head -1)
            if [ -n "$vhost_file" ]; then
                sed -i "s/listen [0-9]*/listen $puerto/" "$vhost_file"
                mv "$vhost_file" "/etc/nginx/conf.d/vhost_$puerto.conf" 2>/dev/null
            fi
            if command -v semanage &>/dev/null; then
                semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null ||                 semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
            fi
            ;;
        tomcat)
            sed -i "s/port="[0-9]*"/port="$puerto"/" /etc/tomcat/server.xml 2>/dev/null
            if command -v semanage &>/dev/null; then
                semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null ||                 semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
            fi
            ;;
    esac
    firewall-cmd --permanent --add-port="$puerto"/tcp > /dev/null 2>&1
    firewall-cmd --reload > /dev/null 2>&1
    systemctl enable "$servicio" --now 2>/dev/null
    if systemctl restart "$servicio"; then
        echo "  [OK] $nombre levantado correctamente en puerto $puerto."
        echo "  Accede en: http://$(hostname -I | awk '{print $1}'):$puerto"
        verificar_servicio "$servicio" "$puerto"
    else
        echo "  [!!] Error al levantar $nombre."
        echo "       Revisa: journalctl -xe -u $servicio"
    fi
}
flujo_verificacion() {
    echo ""; echo "  ============================================"
    echo "    Verificacion de servicio"
    echo "  ============================================"
    echo "  1) httpd (Apache)   2) nginx   3) tomcat"; echo ""
    local svc_op
    read -p "  Selecciona el servicio (1-3): " svc_op
    local servicio
    case "$svc_op" in
        1) servicio="httpd"  ;;
        2) servicio="nginx"  ;;
        3) servicio="tomcat" ;;
        *) echo "  Opcion invalida." >&2; return ;;
    esac
    local puerto
    read -p "  Ingresa el puerto del servicio: " puerto
    [[ ! "$puerto" =~ ^[0-9]+$ ]] && { echo "  Puerto invalido." >&2; return; }
    verificar_servicio "$servicio" "$puerto"
}
main() {
    if [ "$EUID" -ne 0 ]; then
        echo ""; echo "  ERROR: Ejecuta el script con sudo:"
        echo "  sudo bash aprovisionamiento_fedora.sh"; echo ""; exit 1
    fi
    if ! grep -qi "fedora\|rhel\|centos\|rocky\|alma" /etc/os-release 2>/dev/null; then
        echo "  ADVERTENCIA: Este script esta disenado para Fedora/RHEL."
        echo "  Para Debian/Ubuntu usa aprovisionamiento_linux.sh"
        echo ""
        read -p "  Continuar de todas formas? [s/N]: " forzar
        [[ ! "$forzar" =~ ^[sS]$ ]] && exit 1
    fi
    while true; do
        mostrar_banner
        menu_principal
        opcion=$(leer_opcion)
        case "$opcion" in
            1) flujo_instalacion "apache" "Apache (httpd)" ;;
            2) flujo_instalacion "nginx"  "Nginx" ;;
            3) flujo_instalacion "tomcat" "Tomcat" ;;
            4) flujo_verificacion ;;
            5) desinstalar_servidor ;;
            6) cambiar_version ;;
            7)
                echo ""
                read -p "  Seguro que deseas purgar todos los servidores? [s/N]: " conf
                [[ "$conf" =~ ^[sS]$ ]] && liberar_entorno
                ;;
            8) levantar_servicio ;;
            0)
                echo ""; echo "  Saliendo. Hasta luego!"; echo ""; exit 0 ;;
        esac
        echo ""; read -p "  Presiona ENTER para volver al menu..."
    done
}
main
