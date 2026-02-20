#!/bin/bash

# --- COLORES Y LOGS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[AVISO]${NC} $1"; }

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
        
        # Si es opcional y está vacío
        if [ "$tipo" == "opcional" ] && [ -z "$ip_input" ]; then
            echo ""
            return 0
        fi

        # Si es obligatorio y está vacío
        if [ -z "$ip_input" ]; then
             log_error "El campo no puede estar vacío."
             continue
        fi

        # Validación de formato y rangos
        if [[ $ip_input =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            OIFS=$IFS; IFS='.'; ip_arr=($ip_input); IFS=$OIFS
            if [[ ${ip_arr[0]} -le 255 && ${ip_arr[1]} -le 255 && ${ip_arr[2]} -le 255 && ${ip_arr[3]} -le 255 ]]; then
                
                # Reglas de IPs Prohibidas
                if [[ "$ip_input" == "0.0.0.0" ]]; then
                    log_error "IP 0.0.0.0 no permitida."
                    continue
                elif [[ "$ip_input" == "127.0.0.1" ]]; then
                    log_error "IP 127.0.0.1 no permitida."
                    continue
                elif [[ "$ip_input" == "255.255.255.255" ]]; then
                    log_error "IP Broadcast Global no permitida."
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

# --- VERIFICACIÓN DE IP ESTÁTICA ---
verificar_ip_fija() {
    log_info "Comprobando configuración de red..."
    if grep -q "inet static" /etc/network/interfaces; then
        log_ok "Se detectó configuración de IP estática en el sistema."
    else
        log_warn "El servidor NO tiene una IP estática configurada permanentemente."
        read -p "¿Deseas configurar una IP estática ahora? (s/n): " resp
        if [[ "$resp" == "s" || "$resp" == "S" ]]; then
            echo "Interfaces disponibles:"
            ip link show | grep "enp" | awk -F: '{print $2}' | tr -d ' '
            read -p "Nombre del Adaptador (ej. enp0s8): " INT_IFACE
            if [ -z "$INT_IFACE" ]; then log_error "Interfaz vacía."; return; fi
            
            IP_NUEVA=$(pedir_ip_custom "IP Estática del Servidor")
            MASCARA=$(pedir_ip_custom "Máscara de Subred (ej. 255.255.255.0)")
            GW=$(pedir_ip_custom "Gateway (Enter para omitir)" "opcional")

            cp /etc/network/interfaces /etc/network/interfaces.bak
            cat > /etc/network/interfaces <<EOF
source /etc/network/interfaces.d/*
auto lo
iface lo inet loopback

auto $INT_IFACE
iface $INT_IFACE inet static
    address $IP_NUEVA
    netmask $MASCARA
EOF
            if [ ! -z "$GW" ]; then echo "    gateway $GW" >> /etc/network/interfaces; fi
            
            ip addr flush dev $INT_IFACE
            ip addr add $IP_NUEVA/$MASCARA dev $INT_IFACE 2>/dev/null
            ip link set $INT_IFACE up
            log_ok "IP Estática $IP_NUEVA configurada correctamente."
        fi
    fi
}

# ====================================================================
# MÓDULO DHCP 
# ====================================================================

instalar_dhcp() {
    log_info "Verificando instalación de DHCP..."
    if ! dpkg -s isc-dhcp-server >/dev/null 2>&1; then
        log_warn "Instalando isc-dhcp-server..."
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y isc-dhcp-server
        if [ $? -eq 0 ]; then log_ok "Instalado correctamente."; else log_error "Fallo al instalar."; fi
    else
        log_ok "El software DHCP ya estaba instalado (Idempotencia)."
    fi
    read -p "Enter para continuar..."
}

# --- 2. CONFIGURAR SCOPE (CON MÁSCARA MANUAL) ---
configurar_scope() {
    log_info "--- CONFIGURACIÓN DEL ÁMBITO ---"

    echo "Interfaces disponibles:"
    ip link show | grep "enp" | awk -F: '{print $2}' | tr -d ' '
    echo "------------------------"
    read -p "Nombre del Adaptador (ej. enp0s8): " INT_IFACE
    if [ -z "$INT_IFACE" ]; then log_error "Interfaz vacía."; return; fi

    # 1. Pedir IP Inicial (Servidor)
    RANGE_START=$(pedir_ip_custom "IP Inicio Rango (Será la IP del Servidor)")
    IFS='.' read -r s1 s2 s3 s4 <<< "$RANGE_START"

    # 2. Pedir Máscara de Subred
    NETMASK=$(pedir_ip_custom "Mascara de Subred (ej. 255.255.255.0)")
    IFS='.' read -r m1 m2 m3 m4 <<< "$NETMASK"

    # 3. Validar IP Final
    while true; do
        RANGE_END=$(pedir_ip_custom "IP Fin Rango")
        IFS='.' read -r e1 e2 e3 e4 <<< "$RANGE_END"
        if [[ "$s1.$s2.$s3" == "$e1.$e2.$e3" ]]; then
            if [ "$e4" -le "$s4" ]; then
                log_error "Error: La IP Final debe ser mayor que la Inicial."
                continue
            fi
        fi
        break
    done

    GATEWAY=$(pedir_ip_custom "Gateway (Enter para omitir)" "opcional")
    DNS_INT=$(pedir_ip_custom "DNS (Recomendado: La IP de este servidor)" "opcional")
    
    read -p "Nombre del Scope [local]: " SCOPE_NAME
    [ -z "$SCOPE_NAME" ] && SCOPE_NAME="local"
    
    read -p "Tiempo Lease (seg) [600]: " LEASE_TIME
    [ -z "$LEASE_TIME" ] && LEASE_TIME=600

    n1=$((s1 & m1))
    n2=$((s2 & m2))
    n3=$((s3 & m3))
    n4=$((s4 & m4))
    NETWORK_ID="$n1.$n2.$n3.$n4"

    SERVER_IP=$RANGE_START
    DHCP_START_OCTET=$((s4 + 1))
    DHCP_START_IP="$s1.$s2.$s3.$DHCP_START_OCTET"

    log_info "Calculando Red..."
    log_info " -> IP Servidor: $SERVER_IP"
    log_info " -> Máscara:     $NETMASK"
    log_info " -> ID de Red:   $NETWORK_ID"

    # APLICAR IP ESTÁTICA ORIGINAL
    log_info "Configurando interfaz $INT_IFACE..."
    cp /etc/network/interfaces /etc/network/interfaces.bak 2>/dev/null
    
    grep -v "$INT_IFACE" /etc/network/interfaces > /tmp/interfaces.tmp
    cat > /etc/network/interfaces <<EOF
source /etc/network/interfaces.d/*
auto lo
iface lo inet loopback

auto $INT_IFACE
iface $INT_IFACE inet static
    address $SERVER_IP
    netmask $NETMASK
EOF
    ip addr flush dev $INT_IFACE
    ip addr add $SERVER_IP/$NETMASK dev $INT_IFACE 2>/dev/null
    ip link set $INT_IFACE up

    # GENERAR DHCPD.CONF
    log_info "Generando configuración DHCP..."
    OPT_R=""; if [ ! -z "$GATEWAY" ]; then OPT_R="option routers $GATEWAY;"; fi
    OPT_D=""; if [ ! -z "$DNS_INT" ]; then OPT_D="option domain-name-servers $DNS_INT;"; fi

    cat > /etc/dhcp/dhcpd.conf <<EOF
default-lease-time $LEASE_TIME;
max-lease-time $(($LEASE_TIME * 2));
authoritative;

subnet $NETWORK_ID netmask $NETMASK {
  range $DHCP_START_IP $RANGE_END;
  option domain-name "$SCOPE_NAME.local";
  $OPT_R
  $OPT_D
}
EOF

    # REINICIAR SERVICIO
    sed -i "s/INTERFACESv4=.*/INTERFACESv4=\"$INT_IFACE\"/" /etc/default/isc-dhcp-server
    systemctl restart isc-dhcp-server
    
    if systemctl is-active --quiet isc-dhcp-server; then
        log_ok "Servicio configurado y corriendo exitosamente."
    else
        log_error "Error iniciando servicio."
    fi
    read -p "Enter para continuar..."
}

monitorear_clientes() {
    log_info "Clientes Conectados (Últimos leases):"
    LEASE_FILE="/var/lib/dhcp/dhcpd.leases"
    if [ -f "$LEASE_FILE" ]; then
        grep -E "lease |hardware ethernet|client-hostname" "$LEASE_FILE" | tail -n 15
    else
        log_warn "No hay archivo de leases aún."
    fi
    read -p "Enter para continuar..."
}

# --- VERIFICAR SERVICIOS ---
verificar_servicios() {
    clear
    log_info "--- ESTADO DE LOS SERVICIOS ---"
    
    echo -n "1. Servidor DHCP (isc-dhcp-server): "
    if systemctl is-active --quiet isc-dhcp-server; then
        echo -e "\e[32m[CORRIENDO]\e[0m"
    else
        echo -e "\e[31m[DETENIDO / NO INSTALADO]\e[0m"
    fi
    
    echo -n "2. Servidor DNS (bind9): "
    if systemctl is-active --quiet bind9; then
        echo -e "\e[32m[CORRIENDO]\e[0m"
    else
        echo -e "\e[31m[DETENIDO / NO INSTALADO]\e[0m"
    fi
    
    echo "-------------------------------------"
    read -p "Enter para volver al menú..."
}

desinstalar_dhcp() {
    read -p "¿Eliminar Servidor DHCP? (s/n): " CONF
    if [[ "$CONF" == "s" || "$CONF" == "S" ]]; then
        apt-get remove --purge -y isc-dhcp-server
        log_ok "DHCP Desinstalado."
    fi
    read -p "Enter para continuar..."
}

# ====================================================================
# MÓDULO DNS (BIND9)
# ====================================================================

instalar_dns() {
    log_info "Verificando instalación de BIND9 (DNS)..."
    verificar_ip_fija
    
    if ! dpkg -s bind9 >/dev/null 2>&1; then
        log_warn "Instalando BIND9 y utilidades (bind9, bind9utils, bind9-doc)..."
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y bind9 bind9utils bind9-doc dnsutils
        if [ $? -eq 0 ]; then 
            log_ok "BIND9 instalado correctamente."
            # Asegurar que resolv.conf no estorbe localmente
            systemctl enable bind9
            systemctl start bind9
        else 
            log_error "Fallo al instalar BIND9."
        fi
    else
        log_ok "BIND9 ya está instalado (Idempotencia)."
    fi
    read -p "Enter para continuar..."
}

agregar_dominio() {
    log_info "--- GESTOR ABC: AGREGAR DOMINIO ---"
    read -p "Ingresa el nombre del dominio (ej. reprobados.com): " DOMINIO
    if [ -z "$DOMINIO" ]; then log_error "Dominio inválido."; return; fi

    ZONAS_CONF="/etc/bind/named.conf.local"
    ARCHIVO_ZONA="/var/cache/bind/db.$DOMINIO"

    if grep -q "zone \"$DOMINIO\"" "$ZONAS_CONF"; then
        log_warn "El dominio $DOMINIO ya existe en la configuración. (Idempotencia)"
        read -p "Enter para continuar..."
        return
    fi

    # =================================================================
    # CANDADO DE IP: IMPIDE GUARDAR HASTA QUE SEA 100% VALIDA
    while true; do
        read -p "Ingresa la IP que resolverá este dominio (ej. 55.55.55.55): " IP_SERVIDOR
        
        if [ -z "$IP_SERVIDOR" ]; then
            echo -e "\e[31m[ERROR] No puedes dejarlo vacío. Intenta de nuevo.\e[0m"
            continue
        fi

        if [[ "$IP_SERVIDOR" == "0.0.0.0" || "$IP_SERVIDOR" == "127.0.0.1" || "$IP_SERVIDOR" == "255.255.255.255" ]]; then
            echo -e "\e[31m[ERROR] IP $IP_SERVIDOR NO permitida. Escribe una IP real.\e[0m"
            continue
        fi

        if [[ $IP_SERVIDOR =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
            if [[ ${BASH_REMATCH[1]} -le 255 && ${BASH_REMATCH[2]} -le 255 && ${BASH_REMATCH[3]} -le 255 && ${BASH_REMATCH[4]} -le 255 ]]; then
                break 
            else
                echo -e "\e[31m[ERROR] Ningún número de la IP puede ser mayor a 255.\e[0m"
            fi
        else
            echo -e "\e[31m[ERROR] Formato inválido. Escribe 4 números separados por puntos.\e[0m"
        fi
    done
    # =================================================================

    log_info "1. Declarando Zona Directa en $ZONAS_CONF..."
    cat <<EOF >> "$ZONAS_CONF"
zone "$DOMINIO" {
    type master;
    file "$ARCHIVO_ZONA";
};
EOF

    log_info "2. Generando archivo de Zona Directa ($ARCHIVO_ZONA)..."
    cat <<EOF > "$ARCHIVO_ZONA"
\$TTL    604800
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
www     IN      CNAME   $DOMINIO.
EOF

    # =================================================================
    # 3. CREACIÓN DE ZONA INVERSA (PTR) AUTOMÁTICA
    # =================================================================
    # Extraemos los octetos de la IP
    IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$IP_SERVIDOR"
    
    # Invertimos los 3 primeros octetos para el estándar in-addr.arpa
    RED_INVERSA="${ip3}.${ip2}.${ip1}.in-addr.arpa"
    ARCHIVO_ZONA_INVERSA="/var/cache/bind/db.${ip1}.${ip2}.${ip3}"

    log_info "3. Declarando Zona Inversa ($RED_INVERSA)..."
    # Solo la declara en named.conf.local si no existe aún
    if ! grep -q "zone \"$RED_INVERSA\"" "$ZONAS_CONF"; then
        cat <<EOF >> "$ZONAS_CONF"
zone "$RED_INVERSA" {
    type master;
    file "$ARCHIVO_ZONA_INVERSA";
};
EOF
    fi

    log_info "4. Generando archivo PTR..."
    # Si el archivo inverso no existe, creamos su cabecera SOA
    if [ ! -f "$ARCHIVO_ZONA_INVERSA" ]; then
        cat <<EOF > "$ARCHIVO_ZONA_INVERSA"
\$TTL    604800
@       IN      SOA     ns1.$DOMINIO. admin.$DOMINIO. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMINIO.
EOF
    fi
    
    # Inyectamos el registro PTR apuntando el último octeto de la IP hacia el dominio
    # (Ojo: En BIND9 los dominios deben terminar con un punto final)
    if ! grep -q "^$ip4 .* PTR .* $DOMINIO\.$" "$ARCHIVO_ZONA_INVERSA"; then
        echo "$ip4      IN      PTR     $DOMINIO." >> "$ARCHIVO_ZONA_INVERSA"
    fi
    # =================================================================

    log_ok "Zonas (Directa/Inversa) y Registros (A, CNAME, PTR) creados exitosamente."
    systemctl restart bind9
    read -p "Enter para continuar..."
}

eliminar_dominio() {
    log_info "--- GESTOR ABC: ELIMINAR DOMINIO ---"
    ZONAS_CONF="/etc/bind/named.conf.local"
    
    echo "Dominios actuales configurados:"
    grep "zone " "$ZONAS_CONF" | awk -F'"' '{print "- "$2}'
    echo "--------------------------------"
    
    read -p "Ingresa el nombre exacto del dominio a eliminar: " DOMINIO
    if [ -z "$DOMINIO" ]; then return; fi

    ARCHIVO_ZONA="/var/cache/bind/db.$DOMINIO"

    if grep -q "zone \"$DOMINIO\"" "$ZONAS_CONF"; then
        
        sed -i "/zone \"$DOMINIO\" {/,/};/d" "$ZONAS_CONF"
        log_ok "Dominio borrado de $ZONAS_CONF."
        
        if [ -f "$ARCHIVO_ZONA" ]; then
            rm "$ARCHIVO_ZONA"
            log_ok "Archivo de zona físico eliminado."
        fi
        systemctl restart bind9
    else
        log_error "El dominio no existe en la configuración."
    fi
    read -p "Enter para continuar..."
}
# --- GESTOR ABC: LISTAR DOMINIOS ACTIVOS ---
listar_dominios() {
    log_info "--- GESTOR ABC: CONSULTA DE DOMINIOS ACTIVOS ---"
    
    # Verificamos si BIND9 existe
    if [ ! -f /etc/bind/named.conf.local ]; then
        log_error "El servidor BIND9 no está instalado o configurado."
        read -p "Enter para continuar..."
        return
    fi

    # Contamos cuántas zonas hay registradas
    TOTAL_DOMINIOS=$(grep -c "zone " /etc/bind/named.conf.local)
    
    if [ "$TOTAL_DOMINIOS" -eq 0 ]; then
        echo -e "\n[INFO] No hay ningún dominio registrado actualmente en el servidor."
    else
        echo -e "\n=================================================="
        printf "%-30s | %-15s\n" "DOMINIO" "IP DEL SERVIDOR"
        echo "-------------------------------+------------------"
        
        # Extraemos los dominios y buscamos su IP en su archivo de configuración
        grep "zone " /etc/bind/named.conf.local | awk -F'"' '{print $2}' | while read dominio; do
            archivo_zona=$(grep -A 2 "zone \"$dominio\"" /etc/bind/named.conf.local | grep "file" | awk -F'"' '{print $2}')
            
            if [ -f "$archivo_zona" ]; then
                # Busca el registro A principal (excluyendo el de www)
                ip=$(grep -w "A" "$archivo_zona" | grep -v "www" | head -n 1 | awk '{print $NF}')
                printf "%-30s | %-15s\n" "$dominio" "$ip"
            else
                printf "%-30s | %-15s\n" "$dominio" "[Error: Sin archivo]"
            fi
        done
        echo "=================================================="
    fi
    
    echo ""
    read -p "Enter para continuar..."
}

validar_dns() {
    log_info "--- MÓDULO DE PRUEBAS Y VALIDACIÓN ---"
    read -p "Ingresa el dominio a validar (ej. reprobados.com): " DOMINIO
    ARCHIVO_ZONA="/var/cache/bind/db.$DOMINIO"

    log_info "1. Verificando Sintaxis Global (named-checkconf)..."
    if named-checkconf; then 
        log_ok "Sintaxis del servidor correcta."
    else 
        log_error "Errores de sintaxis detectados."
    fi

    log_info "2. Verificando Zona Específica (named-checkzone)..."
    if [ -f "$ARCHIVO_ZONA" ]; then
        if named-checkzone "$DOMINIO" "$ARCHIVO_ZONA"; then
            log_ok "Archivo de zona válido."
        else
            log_error "Errores en el archivo de zona."
        fi
    else
        log_error "No se encontró el archivo $ARCHIVO_ZONA"
    fi

    log_info "3. Prueba de Resolución Local (nslookup y ping)..."
    # Forzamos a que pregunte al localhost para evitar que el DNS externo responda
    nslookup "$DOMINIO" 127.0.0.1
    echo "---------------------------"
    ping -c 2 "www.$DOMINIO"

    read -p "Enter para continuar..."
}

desinstalar_dns() {
    read -p "¿Eliminar Servidor DNS (BIND9) y todos sus archivos? (s/n): " CONF
    if [[ "$CONF" == "s" || "$CONF" == "S" ]]; then
        apt-get remove --purge -y bind9 bind9utils bind9-doc
        rm -rf /etc/bind
        rm -rf /var/cache/bind
        log_ok "DNS Desinstalado."
    fi
    read -p "Enter para continuar..."
}

check_root

while true; do
    clear
    echo "========= SERVIDOR DHCP & DNS ========="
    echo "1) Instalar DHCP"
    echo "2) Configurar Scope DHCP"
    echo "3) Monitorear Clientes DHCP"
    echo "4) Instalar DNS"
    echo "5) Agregar Dominio"
    echo "6) Listar Dominios"
    echo "7) Validar DNS"
    echo "8) Salir"
    echo "========================================"
    read -p "Selecciona una opción: " op

    case $op in
        1) instalar_dhcp ;;
        2) configurar_scope ;;
        3) monitorear_clientes ;;
        4) instalar_dns ;;
        5) agregar_dominio ;;
        6) listar_dominios ;;
        7) validar_dns ;;
        8) exit 0 ;;
        *) echo "Opción inválida"; sleep 1 ;;
    esac
done
