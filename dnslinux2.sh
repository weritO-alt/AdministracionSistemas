#!/bin/bash

# ---------------------------------------------------
# 1. FUNCIONES PARA MENSAJES Y VALIDACIONES
# ---------------------------------------------------

log_exito() { echo "[OK] $1"; }
log_error() { echo "[ERROR] $1"; }
log_aviso() { echo "[INFO] $1"; }

verificar_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Debes ejecutar este script como root o con sudo."
        exit 1
    fi
}

pedir_entero() {
    local mensaje="$1"
    while true; do
        read -p "$mensaje: " num
        if [[ -z "$num" ]]; then
            log_error "No puede estar vacio."
        elif [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -gt 0 ]; then
            echo "$num"
            return
        else
            log_error "Solo numeros enteros positivos."
        fi
    done
}

validar_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$ip"
        if [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ]; then
            if [ "$ip" != "0.0.0.0" ] && [ "$ip" != "127.0.0.1" ] && [ "$ip" != "255.255.255.255" ]; then
                return 0
            fi
        fi
    fi
    return 1
}

pedir_ip() {
    local mensaje="$1"
    local opcional="${2:-no}"
    while true; do
        read -p "$mensaje: " ip
        if [ "$opcional" == "si" ] && [ -z "$ip" ]; then
            echo ""
            return
        fi
        if [ -z "$ip" ]; then
            log_error "No lo dejes vacio."
            continue
        fi
        if validar_ip "$ip"; then
            echo "$ip"
            return
        else
            log_error "Formato incorrecto o IP reservada. Usa X.X.X.X (0-255)."
        fi
    done
}

obtener_prefijo_desde_mascara() {
    local mascara="$1"
    case "$mascara" in
        "255.255.255.0") echo "24" ;;
        "255.255.0.0")   echo "16" ;;
        "255.0.0.0")     echo "8"  ;;
        *) echo "24" ;;
    esac
}

# ---------------------------------------------------
# 2. MODULO DHCP
# ---------------------------------------------------

instalar_dhcp() {
    log_aviso "Verificando DHCP..."
    if rpm -q dhcp-server &>/dev/null; then
        log_exito "DHCP ya instalado."
    else
        log_aviso "Instalando dhcp-server..."
        dnf install -y dhcp-server
        if rpm -q dhcp-server &>/dev/null; then
            log_exito "Instalacion completa."
        else
            log_error "Fallo la instalacion de DHCP."
            read -p "Enter para continuar..."
            return
        fi
    fi

    log_aviso "Habilitando servicio DHCP..."
    systemctl enable dhcpd
    read -p "Enter para continuar..."
}

configurar_scope() {
    if ! rpm -q dhcp-server &>/dev/null; then
        log_error "DHCP no esta instalado. Instala primero (Opcion 1)."
        read -p "Enter para continuar..."
        return
    fi

    log_aviso "--- CONFIGURACION DE RED Y SCOPE DHCP ---"

    echo "Interfaces disponibles:"
    nmcli device status
    read -p "Nombre de la interfaz [Default: ens33]: " interfaz
    [ -z "$interfaz" ] && interfaz="ens33"

    # Verificar si ya tiene IP fija
    ip_actual=$(nmcli -g IP4.ADDRESS device show "$interfaz" 2>/dev/null | cut -d'/' -f1)
    if [ -n "$ip_actual" ]; then
        log_aviso "La interfaz ya tiene IP: $ip_actual"
        read -p "Deseas cambiarla? (s/n): " cambiar
        if [ "$cambiar" != "s" ]; then
            ip_servidor="$ip_actual"
        else
            ip_servidor=$(pedir_ip "IP Estatica del Servidor")
        fi
    else
        ip_servidor=$(pedir_ip "IP Estatica del Servidor")
    fi

    rango_inicio=$(pedir_ip "1. IP Inicio Rango")

    while true; do
        rango_fin=$(pedir_ip "2. IP Fin Rango")
        if [[ "$(echo "$rango_fin" | awk -F. '{print $4}')" -gt "$(echo "$rango_inicio" | awk -F. '{print $4}')" ]]; then
            break
        else
            log_error "La IP Final debe ser mayor a $rango_inicio."
        fi
    done

    read -p "3. Prefijo (24, 16, 8) [Default: 24]: " prefijo
    [ -z "$prefijo" ] && prefijo=24

    case "$prefijo" in
        24) mascara="255.255.255.0" ;;
        16) mascara="255.255.0.0" ;;
        8)  mascara="255.0.0.0" ;;
        *)  mascara="255.255.255.0"; prefijo=24 ;;
    esac

    gateway=$(pedir_ip "4. Gateway (Enter para omitir)" "si")
    dns=$(pedir_ip "5. DNS (Recomendado: IP de este servidor)")
    tiempo_lease=$(pedir_entero "6. Tiempo Lease (segundos)")

    # Calcular la red
    IFS='.' read -r a b c d <<< "$rango_inicio"
    red="${a}.${b}.${c}.0"

    log_aviso "Configurando IP estatica en $interfaz..."
    nmcli con mod "$interfaz" ipv4.addresses "${ip_servidor}/${prefijo}"
    nmcli con mod "$interfaz" ipv4.method manual
    if [ -n "$gateway" ]; then
        nmcli con mod "$interfaz" ipv4.gateway "$gateway"
    fi
    nmcli con mod "$interfaz" ipv4.dns "$dns"
    nmcli con up "$interfaz"
    log_exito "IP estatica configurada."

    log_aviso "Generando archivo de configuracion DHCP..."
    cat > /etc/dhcp/dhcpd.conf <<EOF
# Configuracion generada automaticamente
default-lease-time ${tiempo_lease};
max-lease-time $((tiempo_lease * 2));

subnet ${red} netmask ${mascara} {
    range ${rango_inicio} ${rango_fin};
    option domain-name-servers ${dns};
    option subnet-mask ${mascara};
$([ -n "$gateway" ] && echo "    option routers ${gateway};")
}
EOF

    # Configurar en que interfaz escucha DHCP
    sed -i "s/^DHCPDARGS=.*/DHCPDARGS=${interfaz}/" /etc/sysconfig/dhcpd 2>/dev/null || \
    echo "DHCPDARGS=${interfaz}" > /etc/sysconfig/dhcpd

    systemctl restart dhcpd
    if systemctl is-active dhcpd &>/dev/null; then
        log_exito "Scope configurado y servicio DHCP corriendo."
    else
        log_error "El servicio DHCP no pudo iniciar. Revisa /etc/dhcp/dhcpd.conf"
    fi

    # Abrir firewall para DHCP
    firewall-cmd --add-service=dhcp --permanent &>/dev/null
    firewall-cmd --reload &>/dev/null
    log_exito "Firewall configurado para DHCP."

    read -p "Enter para continuar..."
}

ver_clientes_dhcp() {
    log_aviso "CLIENTES CONECTADOS (Leases)"
    if [ -f /var/lib/dhcpd/dhcpd.leases ]; then
        grep -A5 "lease" /var/lib/dhcpd/dhcpd.leases | grep -E "lease|binding|client-hostname"
    else
        log_error "No hay archivo de leases. Puede que no se haya asignado ninguna IP aun."
    fi
    read -p "Enter para continuar..."
}

# ---------------------------------------------------
# 3. MODULO DNS
# ---------------------------------------------------

instalar_dns() {
    clear
    log_aviso "--- INSTALACION DE DNS (BIND9) ---"
    if rpm -q bind &>/dev/null; then
        log_exito "BIND ya instalado."
    else
        log_aviso "Instalando bind bind-utils..."
        dnf install -y bind bind-utils
        if rpm -q bind &>/dev/null; then
            log_exito "BIND instalado correctamente."
        else
            log_error "Fallo la instalacion de BIND."
            read -p "Enter para continuar..."
            return
        fi
    fi

    systemctl enable named
    systemctl start named
    log_exito "Servicio DNS corriendo."
    read -p "Enter para continuar..."
}

agregar_dominio_dns() {
    log_aviso "--- AGREGAR DOMINIO DNS ---"

    if ! rpm -q bind &>/dev/null; then
        log_error "BIND no esta instalado. Instala primero (Opcion 1)."
        read -p "Enter para continuar..."
        return
    fi

    read -p "Nombre del dominio (ej. reprobados.com): " dominio
    if [ -z "$dominio" ]; then
        log_error "El dominio no puede estar vacio."
        read -p "Enter para continuar..."
        return
    fi

    # Verificar si ya existe
    if grep -q "\"$dominio\"" /etc/named.conf 2>/dev/null; then
        log_aviso "El dominio $dominio ya existe."
        read -p "Enter para continuar..."
        return
    fi

    ip=$(pedir_ip "IP para este dominio")

    # Agregar zona en named.conf
    cat >> /etc/named.conf <<EOF

zone "${dominio}" IN {
    type master;
    file "/var/named/db.${dominio}";
    allow-update { none; };
};
EOF

    # Crear archivo de zona
    cat > /var/named/db.${dominio} <<EOF
\$TTL 86400
@   IN  SOA ns1.${dominio}. admin.${dominio}. (
            2024010101  ; Serial
            3600        ; Refresh
            1800        ; Retry
            604800      ; Expire
            86400 )     ; Minimum TTL

@       IN  NS  ns1.${dominio}.
ns1     IN  A   ${ip}
@       IN  A   ${ip}
www     IN  CNAME ${dominio}.
EOF

    chown named:named /var/named/db.${dominio}

    # Verificar sintaxis
    log_aviso "Verificando sintaxis de configuracion..."
    if named-checkconf &>/dev/null; then
        log_exito "Sintaxis correcta."
    else
        log_error "Error de sintaxis en named.conf. Revisa manualmente."
        read -p "Enter para continuar..."
        return
    fi

    if named-checkzone "$dominio" /var/named/db.${dominio} &>/dev/null; then
        log_exito "Zona correcta."
    else
        log_error "Error en el archivo de zona."
    fi

    systemctl restart named

    # Abrir firewall para DNS
    firewall-cmd --add-service=dns --permanent &>/dev/null
    firewall-cmd --reload &>/dev/null

    log_exito "Dominio $dominio agregado correctamente."
    read -p "Enter para continuar..."
}

eliminar_dominio_dns() {
    log_aviso "--- ELIMINAR DOMINIO DNS ---"

    dominios=$(grep "^zone" /etc/named.conf | grep -v "localhost\|0.in-addr\|." | awk '{print $2}' | tr -d '"')

    if [ -z "$dominios" ]; then
        log_aviso "No hay dominios activos para eliminar."
        read -p "Enter para continuar..."
        return
    fi

    log_aviso "Dominios disponibles:"
    echo "$dominios"

    read -p "Nombre exacto del dominio a eliminar: " dominio
    [ -z "$dominio" ] && return

    if grep -q "\"$dominio\"" /etc/named.conf; then
        # Eliminar del named.conf
        sed -i "/zone \"${dominio}\"/,/^};/d" /etc/named.conf
        # Eliminar archivo de zona
        rm -f /var/named/db.${dominio}
        systemctl restart named
        log_exito "Dominio $dominio eliminado."
    else
        log_error "Ese dominio no existe."
    fi
    read -p "Enter para continuar..."
}

listar_dominios_dns() {
    log_aviso "--- DOMINIOS ACTIVOS ---"
    while IFS= read -r linea; do
        dominio=$(echo "$linea" | awk '{print $2}' | tr -d '"')
        if [ -f "/var/named/db.${dominio}" ]; then
            ip=$(grep "^@" /var/named/db.${dominio} | grep "IN  A" | awk '{print $NF}')
            echo "$dominio -> ${ip:-Sin IP}"
        fi
    done < <(grep "^zone" /etc/named.conf | grep -v "localhost\|0.in-addr")
    read -p "Enter para continuar..."
}

# ---------------------------------------------------
# 4. MENUS Y ESTADO
# ---------------------------------------------------

verificar_estado() {
    clear
    log_aviso "--- ESTADO DE LOS SERVICIOS ---"
    for servicio in dhcpd named; do
        if systemctl is-active "$servicio" &>/dev/null; then
            echo "$servicio : [CORRIENDO]"
        else
            echo "$servicio : [DETENIDO/NO INSTALADO]"
        fi
    done
    read -p "Enter para continuar..."
}

submenu_dhcp() {
    while true; do
        clear
        echo "--- SUBMENU DHCP ---"
        echo "1. Instalar DHCP"
        echo "2. Configurar Scope"
        echo "3. Ver clientes"
        echo "4. Desinstalar"
        echo "5. Volver"
        read -p "Opcion: " op
        case "$op" in
            1) instalar_dhcp ;;
            2) configurar_scope ;;
            3) ver_clientes_dhcp ;;
            4)
                read -p "Seguro que quieres desinstalar DHCP? (s/n): " confirm
                if [ "$confirm" == "s" ]; then
                    dnf remove -y dhcp-server
                    log_exito "DHCP desinstalado."
                fi
                ;;
            5) return ;;
        esac
    done
}

submenu_dns() {
    while true; do
        clear
        echo "--- SUBMENU DNS ---"
        echo "1. Instalar DNS"
        echo "2. Agregar Dominio"
        echo "3. Listar Dominios"
        echo "4. Eliminar Dominio"
        echo "5. Desinstalar"
        echo "6. Volver"
        read -p "Opcion: " op
        case "$op" in
            1) instalar_dns ;;
            2) agregar_dominio_dns ;;
            3) listar_dominios_dns ;;
            4) eliminar_dominio_dns ;;
            5)
                read -p "Seguro que quieres desinstalar DNS? (s/n): " confirm
                if [ "$confirm" == "s" ]; then
                    dnf remove -y bind bind-utils
                    log_exito "DNS desinstalado."
                fi
                ;;
            6) return ;;
        esac
    done
}

# ---------------------------------------------------
# INICIO
# ---------------------------------------------------

verificar_root

while true; do
    clear
    echo "--- GESTOR UNIFICADO (FEDORA SERVER) ---"
    echo "1. DHCP"
    echo "2. DNS"
    echo "3. Estado"
    echo "4. Salir"
    read -p "Opcion: " op
    case "$op" in
        1) submenu_dhcp ;;
        2) submenu_dns ;;
        3) verificar_estado ;;
        4) exit 0 ;;
    esac
done
