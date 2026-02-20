#!/bin/bash

# --- COLORES Y LOGS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[AVISO]${NC} $1"; }

# --- VALIDACIÓN ROOT ---
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Acceso denegado. Ejecuta como root."
        exit 1
    fi
}

# --- HERRAMIENTA: INPUT DE IP (VALIDADOR) ---
pedir_ip_custom() {
    local mensaje=$1
    local tipo=$2
    local ip_input

    while true; do
        read -p "$mensaje: " ip_input

        if [ "$tipo" == "opcional" ] && [ -z "$ip_input" ]; then
            echo ""
            return 0
        fi

        if [ -z "$ip_input" ]; then
            log_error "El campo no puede estar vacío."
            continue
        fi

        if [[ $ip_input =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            OIFS=$IFS; IFS='.'; ip_arr=($ip_input); IFS=$OIFS
            if [[ ${ip_arr[0]} -le 255 && ${ip_arr[1]} -le 255 && ${ip_arr[2]} -le 255 && ${ip_arr[3]} -le 255 ]]; then
                if [[ "$ip_input" == "0.0.0.0" || "$ip_input" == "127.0.0.1" || "$ip_input" == "255.255.255.255" ]]; then
                    log_error "IP no permitida."
                    continue
                else
                    echo "$ip_input"
                    return 0
                fi
            else
                log_error "Octetos deben ser 0-255."
            fi
        else
            log_error "Formato incorrecto (X.X.X.X)."
        fi
    done
}

# --- CONVERTIR MÁSCARA A CIDR ---
mask2cidr() {
    local nbits=0
    local IFS=.
    for dec in $1; do
        case $dec in
            255) nbits=$((nbits+8));;
            254) nbits=$((nbits+7));;
            252) nbits=$((nbits+6));;
            248) nbits=$((nbits+5));;
            240) nbits=$((nbits+4));;
            224) nbits=$((nbits+3));;
            192) nbits=$((nbits+2));;
            128) nbits=$((nbits+1));;
            0)   ;;
            *)   echo "Error: Máscara inválida $dec"; exit 1;;
        esac
    done
    echo "$nbits"
}

# --- VERIFICACIÓN DE IP ESTÁTICA ---
verificar_ip_fija() {
    log_info "Comprobando configuración de red..."
    echo "Interfaces disponibles:"
    nmcli device status | grep "ethernet"

    read -p "¿Deseas configurar una IP estática ahora? (s/n): " resp
    if [[ "$resp" == "s" || "$resp" == "S" ]]; then
        read -p "Nombre del Dispositivo (DEVICE, ej. enp0s3): " INT_IFACE
        if [ -z "$INT_IFACE" ]; then log_error "Interfaz vacía."; return; fi

        CON_NAME=$(nmcli -t -f NAME,DEVICE connection show | grep ":$INT_IFACE" | cut -d: -f1 | head -n 1)

        if [ -z "$CON_NAME" ]; then
            log_warn "No hay conexión activa, creando una nueva..."
            CON_NAME="Conexion-$INT_IFACE"
            nmcli con add type ethernet con-name "$CON_NAME" ifname "$INT_IFACE"
        fi

        IP_NUEVA=$(pedir_ip_custom "IP Estática del Servidor")
        MASCARA=$(pedir_ip_custom "Máscara de Subred (ej. 255.255.255.0)")
        CIDR=$(mask2cidr $MASCARA)
        GW=$(pedir_ip_custom "Gateway (Enter para omitir)" "opcional")
        DNS_SRV=$(pedir_ip_custom "DNS Primario (Enter para omitir)" "opcional")

        log_info "Aplicando configuración con NetworkManager..."
        nmcli con mod "$CON_NAME" ipv4.addresses "$IP_NUEVA/$CIDR"
        [ -n "$GW" ] && nmcli con mod "$CON_NAME" ipv4.gateway "$GW"
        [ -n "$DNS_SRV" ] && nmcli con mod "$CON_NAME" ipv4.dns "$DNS_SRV"
        nmcli con mod "$CON_NAME" ipv4.method manual
        nmcli con up "$CON_NAME"

        log_ok "IP Estática $IP_NUEVA/$CIDR configurada en $INT_IFACE."
    fi
}

# ====================================================================
# MÓDULO DHCP (FEDORA)
# ====================================================================

instalar_dhcp() {
    log_info "Verificando instalación de DHCP..."
    if ! rpm -q dhcp-server >/dev/null 2>&1; then
        log_warn "Instalando dhcp-server..."
        dnf install -y dhcp-server
        if [ $? -eq 0 ]; then log_ok "Instalado correctamente."; else log_error "Fallo al instalar."; return; fi
    else
        log_ok "El software DHCP ya estaba instalado."
    fi

    log_info "Configurando Firewalld para DHCP..."
    firewall-cmd --permanent --add-service=dhcp
    firewall-cmd --reload

    read -p "Enter para continuar..."
}

configurar_scope() {
    log_info "--- CONFIGURACIÓN DEL ÁMBITO ---"

    RANGE_START=$(pedir_ip_custom "IP Inicio Rango DHCP")
    IFS='.' read -r s1 s2 s3 s4 <<< "$RANGE_START"

    NETMASK=$(pedir_ip_custom "Mascara de Subred (ej. 255.255.255.0)")

    while true; do
        RANGE_END=$(pedir_ip_custom "IP Fin Rango DHCP")
        IFS='.' read -r e1 e2 e3 e4 <<< "$RANGE_END"
        if [[ "$s1.$s2.$s3" == "$e1.$e2.$e3" ]]; then
            if [ "$e4" -le "$s4" ]; then
                log_error "Error: La IP Final debe ser mayor que la Inicial."
                continue
            fi
        fi
        break
    done

    GATEWAY=$(pedir_ip_custom "Gateway para clientes" "opcional")
    DNS_INT=$(pedir_ip_custom "DNS para clientes" "opcional")

    read -p "Nombre del Dominio [local]: " SCOPE_NAME
    [ -z "$SCOPE_NAME" ] && SCOPE_NAME="local"

    IFS='.' read -r m1 m2 m3 m4 <<< "$NETMASK"
    n1=$((s1 & m1)); n2=$((s2 & m2)); n3=$((s3 & m3)); n4=$((s4 & m4))
    NETWORK_ID="$n1.$n2.$n3.$n4"

    log_info "Generando configuración DHCP en /etc/dhcp/dhcpd.conf..."
    OPT_R=""; [ -n "$GATEWAY" ] && OPT_R="option routers $GATEWAY;"
    OPT_D=""; [ -n "$DNS_INT" ] && OPT_D="option domain-name-servers $DNS_INT;"

    cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak 2>/dev/null

    cat > /etc/dhcp/dhcpd.conf <<EOF
default-lease-time 600;
max-lease-time 7200;
authoritative;

subnet $NETWORK_ID netmask $NETMASK {
  range $RANGE_START $RANGE_END;
  option domain-name "$SCOPE_NAME";
  $OPT_R
  $OPT_D
}
EOF

    systemctl enable dhcpd
    systemctl restart dhcpd

    if systemctl is-active --quiet dhcpd; then
        log_ok "Servicio DHCP (dhcpd) corriendo exitosamente."
    else
        log_error "Error iniciando servicio dhcpd. Revisa 'journalctl -xeu dhcpd'."
    fi
    read -p "Enter para continuar..."
}

monitorear_clientes() {
    log_info "Clientes Conectados (Últimos leases):"
    LEASE_FILE="/var/lib/dhcpd/dhcpd.leases"
    if [ -f "$LEASE_FILE" ]; then
        grep -E "lease |hardware ethernet|client-hostname" "$LEASE_FILE" | tail -n 15
    else
        log_warn "No hay archivo de leases aún ($LEASE_FILE)."
    fi
    read -p "Enter para continuar..."
}

# ====================================================================
# MÓDULO DNS (BIND/NAMED FEDORA)
# ====================================================================

instalar_dns() {
    log_info "Verificando instalación de BIND (named)..."

    if ! rpm -q bind >/dev/null 2>&1; then
        log_warn "Instalando bind y bind-utils..."
        dnf install -y bind bind-utils
        if [ $? -eq 0 ]; then
            log_ok "BIND instalado correctamente."
            systemctl enable named
        else
            log_error "Fallo al instalar BIND."
            return
        fi
    else
        log_ok "BIND ya está instalado."
    fi

    log_info "Ajustando /etc/named.conf para permitir consultas externas..."
    sed -i 's/listen-on port 53 { 127.0.0.1; };/listen-on port 53 { any; };/' /etc/named.conf
    sed -i 's/allow-query     { localhost; };/allow-query     { any; };/' /etc/named.conf

    # Restaurar permisos correctos tras modificar con sed
    chown root:named /etc/named.conf
    chmod 640 /etc/named.conf
    restorecon -v /etc/named.conf 2>/dev/null

    log_info "Configurando Firewalld para DNS..."
    firewall-cmd --permanent --add-service=dns
    firewall-cmd --reload

    systemctl enable named
    log_ok "BIND listo. Ahora ve a 'Agregar Dominio' para configurar zonas e iniciar el servicio."
    read -p "Enter para continuar..."
}

agregar_dominio() {
    log_info "--- GESTOR ABC: AGREGAR DOMINIO ---"
    read -p "Ingresa el nombre del dominio (ej. reprobados.com): " DOMINIO
    if [ -z "$DOMINIO" ]; then log_error "Dominio inválido."; return; fi

    CONF_MAIN="/etc/named.conf"
    DIR_ZONAS="/var/named"
    ARCHIVO_ZONA="$DIR_ZONAS/$DOMINIO.db"

    if grep -q "zone \"$DOMINIO\"" "$CONF_MAIN"; then
        log_warn "El dominio $DOMINIO ya existe en la configuración."
        return
    fi

    IP_SERVIDOR=$(pedir_ip_custom "Ingresa la IP que resolverá este dominio")

    log_info "1. Declarando Zona Directa en $CONF_MAIN..."
    cat >> "$CONF_MAIN" <<EOF

zone "$DOMINIO" IN {
    type master;
    file "$DOMINIO.db";
    allow-update { none; };
};
EOF
    chown root:named "$CONF_MAIN"
    chmod 640 "$CONF_MAIN"
    restorecon -v "$CONF_MAIN" 2>/dev/null

    log_info "2. Generando archivo de Zona ($ARCHIVO_ZONA)..."
    cat > "$ARCHIVO_ZONA" <<EOF
\$TTL    86400
@       IN      SOA     ns1.$DOMINIO. admin.$DOMINIO. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMINIO.
@       IN      A       $IP_SERVIDOR
ns1     IN      A       $IP_SERVIDOR
www     IN      CNAME   ns1.$DOMINIO.
EOF

    chown root:named "$ARCHIVO_ZONA"
    chmod 640 "$ARCHIVO_ZONA"

    IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$IP_SERVIDOR"
    RED_INVERSA="${ip3}.${ip2}.${ip1}.in-addr.arpa"
    ARCHIVO_ZONA_INVERSA="$DIR_ZONAS/$ip1.$ip2.$ip3.db"

    if ! grep -q "zone \"$RED_INVERSA\"" "$CONF_MAIN"; then
        log_info "3. Declarando Zona Inversa..."
        cat >> "$CONF_MAIN" <<EOF

zone "$RED_INVERSA" IN {
    type master;
    file "$ip1.$ip2.$ip3.db";
    allow-update { none; };
};
EOF
        chown root:named "$CONF_MAIN"
        chmod 640 "$CONF_MAIN"
        restorecon -v "$CONF_MAIN" 2>/dev/null
    fi

    if [ ! -f "$ARCHIVO_ZONA_INVERSA" ]; then
        cat > "$ARCHIVO_ZONA_INVERSA" <<EOF
\$TTL    86400
@       IN      SOA     ns1.$DOMINIO. admin.$DOMINIO. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMINIO.
EOF
        chown root:named "$ARCHIVO_ZONA_INVERSA"
        chmod 640 "$ARCHIVO_ZONA_INVERSA"
    fi

    if ! grep -q "^$ip4.*PTR.*$DOMINIO\.$" "$ARCHIVO_ZONA_INVERSA"; then
        echo "$ip4      IN      PTR     $DOMINIO." >> "$ARCHIVO_ZONA_INVERSA"
    fi

    systemctl restart named
    if systemctl is-active --quiet named; then
        log_ok "DNS Recargado exitosamente."
    else
        log_error "Error en DNS. Verifica 'systemctl status named'."
    fi
    read -p "Enter para continuar..."
}

listar_dominios() {
    log_info "Dominios configurados en /etc/named.conf:"
    grep "zone " /etc/named.conf | awk -F'"' '{print $2}'
    read -p "Enter para continuar..."
}

eliminar_dominio() {
    log_info "--- ELIMINAR DOMINIO ---"
    log_info "Dominios disponibles:"
    grep "zone " /etc/named.conf | awk -F'"' '{print $2}' | grep -v "^\.$\|^0\.\|^localhost"

    read -p "Ingresa el dominio a eliminar (ej. carlos.com): " DOMINIO
    if [ -z "$DOMINIO" ]; then log_error "Dominio inválido."; return; fi

    CONF_MAIN="/etc/named.conf"
    DIR_ZONAS="/var/named"

    if ! grep -q "zone \"$DOMINIO\"" "$CONF_MAIN"; then
        log_warn "El dominio $DOMINIO no existe en la configuración."
        read -p "Enter para continuar..."
        return
    fi

    read -p "¿Seguro que deseas eliminar $DOMINIO? (s/n): " CONFIRM
    if [[ "$CONFIRM" != "s" && "$CONFIRM" != "S" ]]; then
        log_warn "Operación cancelada."
        read -p "Enter para continuar..."
        return
    fi

    cp "$CONF_MAIN" "$CONF_MAIN.bak"

    sed -i "/^zone \"$DOMINIO\" IN {/,/^};/d" "$CONF_MAIN"

    ARCHIVO_ZONA="$DIR_ZONAS/$DOMINIO.db"
    if [ -f "$ARCHIVO_ZONA" ]; then
        IP_SERVIDOR=$(grep "^@.*IN.*A" "$ARCHIVO_ZONA" | awk '{print $NF}' | head -n 1)
        if [ -n "$IP_SERVIDOR" ]; then
            IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$IP_SERVIDOR"
            RED_INVERSA="${ip3}.${ip2}.${ip1}.in-addr.arpa"
            sed -i "/^zone \"$RED_INVERSA\" IN {/,/^};/d" "$CONF_MAIN"
            rm -f "$DIR_ZONAS/$ip1.$ip2.$ip3.db"
            log_ok "Zona inversa $RED_INVERSA eliminada."
        fi
        rm -f "$ARCHIVO_ZONA"
        log_ok "Archivo de zona $ARCHIVO_ZONA eliminado."
    fi

    chown root:named "$CONF_MAIN"
    chmod 640 "$CONF_MAIN"
    restorecon -v "$CONF_MAIN" 2>/dev/null

    systemctl restart named
    if systemctl is-active --quiet named; then
        log_ok "Dominio $DOMINIO eliminado y DNS recargado exitosamente."
    else
        log_error "Error al recargar DNS. Revisa 'systemctl status named'."
    fi
    read -p "Enter para continuar..."
}

verificar_servicios() {
    clear
    log_info "--- ESTADO DE LOS SERVICIOS (FEDORA) ---"

    echo -n "1. Servidor DHCP (dhcpd): "
    if systemctl is-active --quiet dhcpd; then echo -e "${GREEN}[CORRIENDO]${NC}"; else echo -e "${RED}[DETENIDO]${NC}"; fi

    echo -n "2. Servidor DNS (named):  "
    if systemctl is-active --quiet named; then echo -e "${GREEN}[CORRIENDO]${NC}"; else echo -e "${RED}[DETENIDO]${NC}"; fi

    echo "-------------------------------------"
    read -p "Enter para volver al menú..."
}

# --- VALIDAR ROOT AL INICIO ---
check_root

# --- MENÚ PRINCIPAL ---
while true; do
    clear
    echo -e "${CYAN}--- SCRIPT DE ADMINISTRACIÓN (FEDORA EDITION) ---${NC}"
    echo "1. Verificar/Configurar IP Estática"
    echo "2. Instalar DHCP Server"
    echo "3. Configurar Scope DHCP"
    echo "4. Ver Clientes DHCP (Leases)"
    echo "5. Instalar DNS Server (BIND)"
    echo "6. Agregar Dominio y Zona Inversa"
    echo "7. Listar Dominios"
    echo "8. Estado de Servicios"
    echo "9. Salir"
    echo "------------------------------------------------"
    read -p "Selecciona una opción: " OPCION

    case $OPCION in
        1) verificar_ip_fija ;;
        2) instalar_dhcp ;;
        3) configurar_scope ;;
        4) monitorear_clientes ;;
        5) instalar_dns ;;
        6) agregar_dominio ;;
        7) listar_dominios ;;
        8) verificar_servicios ;;
        9) exit 0 ;;
        *) echo "Opción inválida." ;;
    esac
done
