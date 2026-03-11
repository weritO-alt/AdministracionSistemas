#!/bin/bash

instalar_dependencias_base() {
    echo "Instalando dependencias base y herramientas de políticas..."
    # Añadido policycoreutils para que semanage funcione siempre
    dnf install -y -q curl net-tools firewalld psmisc iproute policycoreutils-python-utils 2>/dev/null
    systemctl enable firewalld --now 2>/dev/null
}

liberar_entorno() {
    echo "Iniciando limpieza profunda del entorno..."
    systemctl stop httpd nginx tomcat 2>/dev/null
    local procesos=("httpd" "nginx" "java")
    for proc in "${procesos[@]}"; do
        pids=$(pgrep -f "$proc")
        [ -n "$pids" ] && kill -9 $pids 2>/dev/null
    done
    dnf remove -y httpd* nginx* tomcat* 2>/dev/null
    dnf autoremove -y 2>/dev/null
    rm -rf /var/www/html/* /var/www/httpd_* /var/www/nginx_* 2>/dev/null
    rm -rf /usr/share/tomcat/webapps/ROOT/* 2>/dev/null
    echo "Entorno limpio."
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
            echo "  Error: Puerto inválido." >&2; continue
        fi
        if [[ " ${reservedPorts[*]} " =~ " ${puerto} " ]]; then
            local desc=${servicios[$puerto]:-"Sistema Critico"}
            echo "  Error: Puerto $puerto reservado para $desc." >&2; continue
        fi
        if ss -tuln | grep -q ":$puerto "; then
            echo "  Error: El puerto $puerto ya está ocupado." >&2; continue
        fi
        break
    done
    echo "$puerto"
}

seleccionar_version() {
    local paquete=$1
    [ "$paquete" == "apache" ] && paquete="httpd"
    # Obtenemos versiones disponibles filtrando arquitectura para evitar errores
    mapfile -t versiones_crudas < <(
        dnf repoquery "$paquete" --available --queryformat "%{version}-%{release}" 2>/dev/null \
        | sort -Vu | tail -n 5
    )
    if [ ${#versiones_crudas[@]} -eq 0 ]; then
        echo "  No se encontraron versiones disponibles." >&2; return 1
    fi
    echo "" >&2
    echo "  Versiones disponibles para $paquete:" >&2
    local i=1
    for ver in "${versiones_crudas[@]}"; do
        echo "    $i) $ver" >&2
        ((i++))
    done
    while true; do
        read -p "  Selecciona el número de versión (1-${#versiones_crudas[@]}): " seleccion
        if [[ "$seleccion" =~ ^[0-9]+$ ]] && [ "$seleccion" -ge 1 ] && [ "$seleccion" -le "${#versiones_crudas[@]}" ]; then
            echo "${versiones_crudas[$((seleccion - 1))]}"; break
        else
            echo "  Error: Selección inválida." >&2
        fi
    done
}

configurar_firewall() {
    local puerto=$1
    firewall-cmd --permanent --add-port="$puerto"/tcp > /dev/null 2>&1
    firewall-cmd --reload > /dev/null 2>&1
}

crear_index() {
    local ruta=$1 servicio=$2 version=$3 puerto=$4
    cat <<EOF > "$ruta/index.html"
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>$servicio</title></head>
<body><h1>Servidor: $servicio</h1><p>Version: $version</p><p>Puerto: $puerto</p></body></html>
EOF
}

crear_usuario_dedicado() {
    local usuario=$1 directorio=$2
    if ! id "$usuario" &>/dev/null; then
        useradd --system --no-create-home --shell /sbin/nologin "$usuario"
    fi
    chown -R "$usuario":"$usuario" "$directorio"
    chmod -R 755 "$directorio"
}

# --- FUNCIONES DE INSTALACION MODIFICADAS ---

instalar_apache() {
    local version=$1 puerto=$2
    echo "  Instalando Apache versión $version en puerto $puerto..."
    # Instalación de versión específica
    dnf install -y "httpd-$version" mod_headers
    
    if ! rpm -q httpd > /dev/null 2>&1; then
        echo "  Error crítico: No se instaló httpd." >&2; return 1
    fi

    local vhost_dir="/var/www/httpd_$puerto"
    mkdir -p "$vhost_dir"
    
    # Configuración de puerto
    sed -i "s/^Listen 80/Listen $puerto/" /etc/httpd/conf/httpd.conf
    
    cat <<EOF > /etc/httpd/conf.d/vhost.conf
<VirtualHost *:$puerto>
    DocumentRoot $vhost_dir
</VirtualHost>
EOF
    
    crear_index "$vhost_dir" "Apache" "$version" "$puerto"
    crear_usuario_dedicado "apache" "$vhost_dir"
    
    # SELinux: Permitir puerto
    semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
    
    configurar_firewall "$puerto"
    systemctl enable httpd --now && systemctl restart httpd
}

instalar_nginx() {
    local version=$1 puerto=$2
    echo "  Instalando Nginx versión $version en puerto $puerto..."
    dnf install -y "nginx-$version"
    
    if ! rpm -q nginx > /dev/null 2>&1; then
        echo "  Error crítico: No se instaló nginx." >&2; return 1
    fi

    local vhost_dir="/var/www/nginx_$puerto"
    mkdir -p "$vhost_dir"
    
    cat <<EOF > /etc/nginx/conf.d/default.conf
server {
    listen $puerto;
    root $vhost_dir;
    index index.html;
}
EOF
    # Comentar el server bloque por defecto para evitar conflictos de puerto
    sed -i 's/listen       80 default_server;/#listen 80;/' /etc/nginx/nginx.conf 2>/dev/null
    
    crear_index "$vhost_dir" "Nginx" "$version" "$puerto"
    crear_usuario_dedicado "nginx" "$vhost_dir"
    
    semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
    
    configurar_firewall "$puerto"
    systemctl enable nginx --now && systemctl restart nginx
}

instalar_tomcat() {
    local version=$1 puerto=$2
    echo "  Instalando Tomcat versión $version..."
    dnf install -y "tomcat-$version" tomcat-webapps java-17-openjdk-headless
    
    sed -i "s/port=\"8080\"/port=\"$puerto\"/g" /etc/tomcat/server.xml
    
    mkdir -p /usr/share/tomcat/webapps/ROOT
    crear_index "/usr/share/tomcat/webapps/ROOT" "Tomcat" "$version" "$puerto"
    
    semanage port -a -t http_port_t -p tcp "$puerto" 2>/dev/null || semanage port -m -t http_port_t -p tcp "$puerto" 2>/dev/null
    
    configurar_firewall "$puerto"
    systemctl enable tomcat --now && systemctl restart tomcat
}

# --- RESTO DEL SCRIPT (VERIFICACION Y MENU) ---

verificar_servicio() {
    local servicio=$1 puerto=$2
    echo -e "\n  [Verificación de $servicio]"
    systemctl is-active --quiet "$servicio" && echo "  - Estado: ACTIVO" || echo "  - Estado: FALLIDO"
    ss -tuln | grep -q ":$puerto " && echo "  - Puerto $puerto: ESCUCHANDO" || echo "  - Puerto $puerto: CERRADO"
}

main() {
    if [ "$EUID" -ne 0 ]; then
        echo "Por favor, ejecuta como root (sudo)."; exit 1
    fi
    
    while true; do
        clear
        echo "  +-----------------------------------------+"
        echo "  |      SISTEMA DE APROVISIONAMIENTO       |"
        echo "  +-----------------------------------------+"
        echo "  1) Instalar Apache       2) Instalar Nginx"
        echo "  3) Instalar Tomcat       4) Limpiar todo"
        echo "  0) Salir"
        read -p "  Opción: " opcion
        
        case "$opcion" in
            1) 
                instalar_dependencias_base
                v=$(seleccionar_version "apache")
                p=$(solicitarPuerto)
                instalar_apache "$v" "$p"
                verificar_servicio "httpd" "$p"
                ;;
            2) 
                instalar_dependencias_base
                v=$(seleccionar_version "nginx")
                p=$(solicitarPuerto)
                instalar_nginx "$v" "$p"
                verificar_servicio "nginx" "$p"
                ;;
            3)
                instalar_dependencias_base
                v=$(seleccionar_version "tomcat")
                p=$(solicitarPuerto)
                instalar_tomcat "$v" "$p"
                verificar_servicio "tomcat" "$p"
                ;;
            4) liberar_entorno ;;
            0) exit 0 ;;
        esac
        read -p "Presiona ENTER para continuar..."
    done
}

main
