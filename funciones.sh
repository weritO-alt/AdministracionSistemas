#!/bin/bash
# ============================================================
# functions.sh — Librería central de funciones
# Fuente para todos los menús de prácticas
# Uso: source "$(dirname "$0")/functions.sh"
# ============================================================

# ────────────────────────────────────────────────────────────
# COLORES
# ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ────────────────────────────────────────────────────────────
# LOGS UNIFICADOS
# ────────────────────────────────────────────────────────────
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }

# Aliases para compatibilidad con scripts anteriores
log_exito() { log_ok "$1"; }
log_aviso() { log_info "$1"; }
log_error() { log_err "$1"; }

# ────────────────────────────────────────────────────────────
# UTILIDADES COMUNES
# ────────────────────────────────────────────────────────────

verificar_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "Este script debe ejecutarse como root."
        log_info "Usa: sudo bash $0"
        exit 1
    fi
}

validar_ip() {
    local ip="$1"
    # Rechazar IPs reservadas
    if [[ "$ip" == "0.0.0.0" || "$ip" == "255.255.255.255" || "$ip" == "127.0.0.1" ]]; then
        return 1
    fi
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$ip"
        if [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]]; then
            return 0
        fi
    fi
    return 1
}

ip_a_numero() {
    local a b c d
    IFS='.' read -r a b c d <<< "$1"
    echo "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
}

pedir_ip() {
    local mensaje="$1"
    local opcional="${2:-no}"
    local ip
    while true; do
        read -rp "$mensaje: " ip
        if [[ "$opcional" == "si" && -z "$ip" ]]; then
            echo ""; return
        fi
        if [[ -z "$ip" ]]; then
            log_err "No puede estar vacío."
            continue
        fi
        if validar_ip "$ip"; then
            echo "$ip"; return
        else
            log_err "Formato incorrecto o IP reservada. Usa X.X.X.X (0-255)."
        fi
    done
}

get_valid_ipaddr() {
    local prompt="$1"
    local ip
    while true; do
        read -rp "$prompt " ip
        if validar_ip "$ip"; then
            echo "$ip"; return 0
        fi
        log_err "IP inválida: '$ip'. Intenta de nuevo."
    done
}

pedir_entero() {
    local mensaje="$1"
    local num
    while true; do
        read -rp "$mensaje: " num
        if [[ -z "$num" ]]; then
            log_err "No puede estar vacío."
        elif [[ "$num" =~ ^[0-9]+$ ]] && [[ "$num" -gt 0 ]]; then
            echo "$num"; return
        else
            log_err "Solo números enteros positivos."
        fi
    done
}

obtener_prefijo_desde_mascara() {
    local mascara="$1"
    case "$mascara" in
        "255.255.255.0") echo "24" ;;
        "255.255.0.0")   echo "16" ;;
        "255.0.0.0")     echo "8"  ;;
        *)               echo "24" ;;
    esac
}

check_package_present() {
    rpm -q "$1" &>/dev/null
}

install_required_package() {
    log_info "Instalando paquete: $1 ..."
    dnf install -y "$1" &>/dev/null
    return $?
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 1 — DHCP BÁSICO
# ────────────────────────────────────────────────────────────

p1_verificar_estado() {
    if systemctl is-active --quiet dhcpd; then
        echo -e "${GREEN}\nEstado del servicio: ACTIVO${NC}"
    else
        echo -e "${RED}\nEstado del servicio: INACTIVO o ERROR${NC}"
        sudo journalctl -u dhcpd -n 5 --no-pager
    fi
    read -p "Presione Enter..."
}

p1_instalar_desinstalar() {
    echo "Escriba 'I' para Instalar o 'D' para Desinstalar"
    read -r accion
    if [[ ${accion^^} == 'I' ]]; then
        sudo dnf install -y dhcp-server
    elif [[ ${accion^^} == 'D' ]]; then
        sudo dnf remove -y dhcp-server
    else
        log_warn "Opción no válida."
    fi
    read -p "Presione Enter..."
}

p1_configurar_ambito() {
    if ! rpm -q dhcp-server &>/dev/null; then
        echo -e "${RED}Error: Instale el rol primero.${NC}"
        read -p "Presione Enter..."
        return
    fi

    read -p "Nombre del nuevo Ámbito: " nombreAmbito

    read -p "IP Inicial: " ipInicio
    validar_ip "$ipInicio" || { echo "IP no válida"; sleep 2; return; }

    read -p "IP Final: " ipFinal
    validar_ip "$ipFinal" || { echo "IP no válida"; sleep 2; return; }

    local inicio_int final_int
    inicio_int=$(ip_a_numero "$ipInicio")
    final_int=$(ip_a_numero "$ipFinal")

    if [[ "$inicio_int" -ge "$final_int" ]]; then
        echo -e "${RED}Error: La IP final debe ser mayor a la inicial.${NC}"
        read -p "Presione Enter..."
        return
    fi

    read -p "Máscara de red: " mascara

    local ltime
    while true; do
        read -p "Lease Time en segundos (Enter = 3600): " ltime
        if [[ -z "$ltime" ]]; then ltime="3600"; break; fi
        if [[ "$ltime" =~ ^[0-9]+$ ]] && [[ "$ltime" -gt 0 ]]; then
            break
        else
            echo -e "${RED}Error: Ingrese un número entero mayor a 0.${NC}"
        fi
    done

    read -p "Gateway (Enter = $ipInicio): " gw
    read -p "DNS (Enter = 8.8.8.8): " dns
    [[ -z "$gw" ]]  && gw="$ipInicio"
    [[ -z "$dns" ]] && dns="8.8.8.8"

    local prefix net_id
    prefix=$(ipcalc -p "$ipInicio" "$mascara" | cut -d= -f2)
    net_id=$(ipcalc -n "$ipInicio" "$mascara" | cut -d= -f2)

    echo -e "${YELLOW}Reconfigurando interfaz enp0s8...${NC}"
    sudo nmcli connection delete enp0s8 &>/dev/null
    sudo nmcli connection add type ethernet ifname enp0s8 con-name enp0s8 \
        ipv4.method manual ipv4.addresses "$ipInicio/$prefix" \
        ipv4.gateway "$gw" ipv4.dns "$dns"
    sudo ip addr flush dev enp0s8
    sudo nmcli connection up enp0s8 &>/dev/null
    sleep 2

    sudo bash -c "cat > /etc/dhcp/dhcpd.conf <<EOF
authoritative;
ddns-update-style none;

subnet $net_id netmask $mascara {
    range $ipInicio $ipFinal;
    option routers $gw;
    option domain-name-servers $dns;
    default-lease-time $ltime;
    max-lease-time $((ltime * 2));
}
EOF"

    sudo mkdir -p /etc/systemd/system/dhcpd.service.d
    sudo bash -c "cat > /etc/systemd/system/dhcpd.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/dhcpd -f -cf /etc/dhcp/dhcpd.conf -user dhcpd -group dhcpd --no-pid enp0s8
EOF"

    sudo systemctl daemon-reload
    sudo systemctl stop dhcpd &>/dev/null
    sudo sh -c "> /var/lib/dhcpd/dhcpd.leases"

    if sudo systemctl start dhcpd; then
        echo -e "${GREEN}¡Servidor DHCP Activo en enp0s8!${NC}"
        echo -e "${GREEN}Configuración: $ipInicio con máscara $mascara${NC}"
        ip addr show enp0s8 | grep "inet "
    else
        echo -e "${RED}Error al iniciar. Revisa journalctl -u dhcpd${NC}"
    fi
    read -p "Presione Enter..."
}

p1_ver_leases() {
    echo -e "${YELLOW}\nLeases activos:${NC}"
    if [[ -f /var/lib/dhcpd/dhcpd.leases ]]; then
        sudo grep -E "lease|hostname|ends" /var/lib/dhcpd/dhcpd.leases
    else
        echo "Sin leases."
    fi
    read -p "Presione Enter..."
}

p1_limpiar_leases() {
    sudo systemctl stop dhcpd
    sudo sh -c "> /var/lib/dhcpd/dhcpd.leases"
    sudo systemctl start dhcpd
    echo -e "${GREEN}Leases limpiados.${NC}"
    read -p "Presione Enter..."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 2 — DHCP AVANZADO
# ────────────────────────────────────────────────────────────

instalar_dhcp() {
    log_aviso "Verificando DHCP..."
    if rpm -q dhcp-server &>/dev/null; then
        log_exito "DHCP ya instalado."
    else
        log_aviso "Instalando dhcp-server..."
        dnf install -y dhcp-server
        if rpm -q dhcp-server &>/dev/null; then
            log_exito "Instalación completa."
        else
            log_error "Falló la instalación de DHCP."
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
        log_error "DHCP no está instalado. Instala primero (Opción 1)."
        read -p "Enter para continuar..."
        return
    fi

    log_aviso "--- CONFIGURACIÓN DE RED Y SCOPE DHCP ---"
    echo "Interfaces disponibles:"
    nmcli device status

    read -p "Nombre de la interfaz [Default: ens33]: " interfaz
    [[ -z "$interfaz" ]] && interfaz="ens33"

    local ip_actual ip_servidor
    ip_actual=$(nmcli -g IP4.ADDRESS device show "$interfaz" 2>/dev/null | cut -d'/' -f1)
    if [[ -n "$ip_actual" ]]; then
        log_aviso "La interfaz ya tiene IP: $ip_actual"
        read -p "¿Deseas cambiarla? (s/n): " cambiar
        if [[ "$cambiar" != "s" ]]; then
            ip_servidor="$ip_actual"
        else
            ip_servidor=$(pedir_ip "IP Estática del Servidor")
        fi
    else
        ip_servidor=$(pedir_ip "IP Estática del Servidor")
    fi

    local rango_inicio rango_fin
    rango_inicio=$(pedir_ip "1. IP Inicio Rango")

    while true; do
        rango_fin=$(pedir_ip "2. IP Fin Rango")
        if [[ "$(echo "$rango_fin" | awk -F. '{print $4}')" -gt \
              "$(echo "$rango_inicio" | awk -F. '{print $4}')" ]]; then
            break
        else
            log_error "La IP Final debe ser mayor a $rango_inicio."
        fi
    done

    read -p "3. Prefijo (24, 16, 8) [Default: 24]: " prefijo
    [[ -z "$prefijo" ]] && prefijo=24
    local mascara
    case "$prefijo" in
        24) mascara="255.255.255.0" ;;
        16) mascara="255.255.0.0" ;;
        8)  mascara="255.0.0.0" ;;
        *)  mascara="255.255.255.0"; prefijo=24 ;;
    esac

    local gateway
    gateway=$(pedir_ip "4. Gateway (Enter para omitir)" "si")

    echo ""
    log_info "DNS primario: ${ip_servidor} (este servidor, forzado automáticamente)"
    local dns_secundario
    dns_secundario=$(pedir_ip "5. DNS Secundario (ej. 8.8.8.8 - Enter para omitir)" "si")

    local tiempo_lease
    tiempo_lease=$(pedir_entero "6. Tiempo Lease (segundos)")

    local red
    IFS='.' read -r a b c d <<< "$rango_inicio"
    red="${a}.${b}.${c}.0"

    log_aviso "Configurando IP estática en $interfaz..."
    nmcli con mod "$interfaz" ipv4.addresses "${ip_servidor}/${prefijo}"
    nmcli con mod "$interfaz" ipv4.method manual
    [[ -n "$gateway" ]] && nmcli con mod "$interfaz" ipv4.gateway "$gateway"

    if [[ -n "$dns_secundario" ]]; then
        nmcli con mod "$interfaz" ipv4.dns "${ip_servidor} ${dns_secundario}"
    else
        nmcli con mod "$interfaz" ipv4.dns "${ip_servidor}"
    fi
    nmcli con up "$interfaz"
    log_exito "IP estática configurada."

    local dns_line
    if [[ -n "$dns_secundario" ]]; then
        dns_line="    option domain-name-servers ${ip_servidor}, ${dns_secundario};"
    else
        dns_line="    option domain-name-servers ${ip_servidor};"
    fi

    log_aviso "Generando archivo de configuración DHCP..."
    cat > /etc/dhcp/dhcpd.conf <<EOF
# Configuración generada automáticamente
default-lease-time ${tiempo_lease};
max-lease-time $((tiempo_lease * 2));

subnet ${red} netmask ${mascara} {
    range ${rango_inicio} ${rango_fin};
${dns_line}
    option subnet-mask ${mascara};
$([ -n "$gateway" ] && echo "    option routers ${gateway};")
}
EOF

    sed -i "s/^DHCPDARGS=.*/DHCPDARGS=${interfaz}/" /etc/sysconfig/dhcpd 2>/dev/null || \
        echo "DHCPDARGS=${interfaz}" > /etc/sysconfig/dhcpd

    systemctl restart dhcpd
    if systemctl is-active dhcpd &>/dev/null; then
        log_exito "Scope configurado y servicio DHCP corriendo."
    else
        log_error "El servicio DHCP no pudo iniciar. Revisa /etc/dhcp/dhcpd.conf"
    fi

    firewall-cmd --add-service=dhcp --permanent &>/dev/null
    firewall-cmd --reload &>/dev/null
    log_exito "Firewall configurado para DHCP."
    read -p "Enter para continuar..."
}

ver_clientes_dhcp() {
    log_aviso "CLIENTES CONECTADOS (Leases)"
    if [[ -f /var/lib/dhcpd/dhcpd.leases ]]; then
        grep -A5 "lease" /var/lib/dhcpd/dhcpd.leases | grep -E "lease|binding|client-hostname"
    else
        log_error "No hay archivo de leases aún."
    fi
    read -p "Enter para continuar..."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 2 — DNS (BIND9)
# ────────────────────────────────────────────────────────────

ZONAS_FILE="/etc/named/custom.zones"

instalar_dns() {
    clear
    log_aviso "--- INSTALACIÓN DE DNS (BIND9) ---"
    if rpm -q bind &>/dev/null; then
        log_exito "BIND ya instalado."
    else
        log_aviso "Instalando bind bind-utils..."
        dnf install -y bind bind-utils
        if rpm -q bind &>/dev/null; then
            log_exito "BIND instalado correctamente."
        else
            log_error "Falló la instalación de BIND."
            read -p "Enter para continuar..."
            return
        fi
    fi

    log_aviso "Configurando named.conf para aceptar consultas externas..."
    if grep -q "allow-query { any; };" /etc/named.conf &&
       grep -q "listen-on port 53 { any; };" /etc/named.conf; then
        log_exito "named.conf ya tiene la configuración correcta."
    else
        sed -i '
/^[[:space:]]*options[[:space:]]*{/ {
    :a
    n
    /^[[:space:]]*};/ b
    /allow-query/d
    /listen-on port/d
    /listen-on-v6/d
    ba
}
' /etc/named.conf
        sed -i '/^[[:space:]]*options[[:space:]]*{/a\
        allow-query { any; };\
        listen-on port 53 { any; };\
        listen-on-v6 port 53 { any; };' /etc/named.conf
        log_exito "named.conf actualizado."
    fi

    if named-checkconf /etc/named.conf 2>/dev/null; then
        log_exito "Configuración de named.conf válida."
    else
        log_error "Error en named.conf. Revisa manualmente."
        read -p "Enter para continuar..."
        return
    fi

    systemctl enable named
    systemctl restart named
    firewall-cmd --add-service=dns --permanent &>/dev/null
    firewall-cmd --reload &>/dev/null
    log_exito "Firewall configurado para DNS."

    sleep 1
    if systemctl is-active named &>/dev/null; then
        log_exito "Servicio DNS corriendo."
    else
        log_error "El servicio named no pudo iniciar."
        journalctl -u named -n 10 --no-pager
    fi
    read -p "Enter para continuar..."
}

preparar_archivo_zonas() {
    mkdir -p /etc/named
    if [[ ! -f "$ZONAS_FILE" ]]; then
        touch "$ZONAS_FILE"
        chown named:named "$ZONAS_FILE"
    fi
    if ! grep -q "custom.zones" /etc/named.conf 2>/dev/null; then
        echo 'include "/etc/named/custom.zones";' >> /etc/named.conf
        log_aviso "Archivo de zonas incluido en named.conf."
    fi
}

revertir_zona() {
    local dominio="$1"
    python3 - <<PYEOF
import re
dominio = "$dominio"
zonas_file = "$ZONAS_FILE"
with open(zonas_file, 'r') as f:
    content = f.read()
pattern = r'\n*zone\s+"' + re.escape(dominio) + r'"\s+IN\s*\{(?:[^{}]|\{[^{}]*\})*\};'
content = re.sub(pattern, '', content, flags=re.DOTALL)
with open(zonas_file, 'w') as f:
    f.write(content)
print("Revertido: " + dominio)
PYEOF
}

reparar_custom_zones() {
    log_aviso "Reconstruyendo $ZONAS_FILE desde archivos válidos en /var/named/..."
    > "$ZONAS_FILE"
    local reparado=0
    for archivo in /var/named/db.*; do
        [[ -f "$archivo" ]] || continue
        local dom="${archivo#/var/named/db.}"
        if named-checkzone "$dom" "$archivo" &>/dev/null; then
            cat >> "$ZONAS_FILE" <<EOF

zone "${dom}" IN {
    type master;
    file "/var/named/db.${dom}";
    allow-update { none; };
};
EOF
            log_exito "Zona recuperada: $dom"
            reparado=$((reparado + 1))
        else
            log_aviso "Zona omitida (archivo inválido): $dom"
        fi
    done
    chown named:named "$ZONAS_FILE"
    log_exito "Reparación completada: $reparado zona(s) recuperada(s)."
    systemctl restart named
    sleep 1
    if systemctl is-active named &>/dev/null; then
        log_exito "named reiniciado correctamente."
    else
        log_error "named no pudo iniciar. Detalle:"
        journalctl -u named -n 15 --no-pager
    fi
    read -p "Enter para continuar..."
}

agregar_dominio_dns() {
    log_aviso "--- AGREGAR DOMINIO DNS ---"
    if ! rpm -q bind &>/dev/null; then
        log_error "BIND no está instalado. Instala primero (Opción 1)."
        read -p "Enter para continuar..."
        return
    fi
    preparar_archivo_zonas

    read -p "Nombre del dominio (ej. reprobados.com): " dominio
    if [[ -z "$dominio" ]]; then
        log_error "El dominio no puede estar vacío."
        read -p "Enter para continuar..."
        return
    fi
    if grep -q "\"$dominio\"" "$ZONAS_FILE" 2>/dev/null; then
        log_aviso "El dominio '$dominio' ya existe."
        read -p "Enter para continuar..."
        return
    fi

    local ip
    ip=$(pedir_ip "IP para este dominio")

    cat > "/var/named/db.${dominio}" <<EOF
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
www     IN  CNAME   ${dominio}.
EOF
    chown named:named "/var/named/db.${dominio}"

    local checkzone_out
    checkzone_out=$(named-checkzone "$dominio" "/var/named/db.${dominio}" 2>&1)
    if ! named-checkzone "$dominio" "/var/named/db.${dominio}" &>/dev/null; then
        log_error "Error en el archivo de zona:"
        echo "$checkzone_out"
        rm -f "/var/named/db.${dominio}"
        read -p "Enter para continuar..."
        return
    fi
    log_exito "Archivo de zona correcto."

    cat >> "$ZONAS_FILE" <<EOF

zone "${dominio}" IN {
    type master;
    file "/var/named/db.${dominio}";
    allow-update { none; };
};
EOF

    log_aviso "Reiniciando named..."
    systemctl restart named
    sleep 1
    if systemctl is-active named &>/dev/null; then
        firewall-cmd --add-service=dns --permanent &>/dev/null
        firewall-cmd --reload &>/dev/null
        log_exito "Dominio '$dominio' agregado con IP $ip."
    else
        log_error "named no pudo iniciar. Revirtiendo cambios..."
        journalctl -u named -n 20 --no-pager
        revertir_zona "$dominio"
        rm -f "/var/named/db.${dominio}"
        systemctl restart named 2>/dev/null
        log_aviso "Si el error persiste, usa 'Reparar DNS' en el menú."
    fi
    read -p "Enter para continuar..."
}

eliminar_dominio_dns() {
    log_aviso "--- ELIMINAR DOMINIO DNS ---"
    preparar_archivo_zonas

    mapfile -t dominios < <(grep "^zone" "$ZONAS_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "${#dominios[@]}" -eq 0 ]]; then
        log_aviso "No hay dominios activos para eliminar."
        read -p "Enter para continuar..."
        return
    fi

    log_aviso "Dominios disponibles:"
    for d in "${dominios[@]}"; do echo "  - $d"; done

    read -p "Nombre exacto del dominio a eliminar: " dominio
    [[ -z "$dominio" ]] && return

    if grep -q "\"${dominio}\"" "$ZONAS_FILE" 2>/dev/null; then
        revertir_zona "$dominio"
        rm -f "/var/named/db.${dominio}"
        systemctl restart named
        sleep 1
        if systemctl is-active named &>/dev/null; then
            log_exito "Dominio '$dominio' eliminado correctamente."
        else
            log_error "named no pudo iniciar. Usa 'Reparar DNS' en el menú."
            journalctl -u named -n 15 --no-pager
        fi
    else
        log_error "El dominio '$dominio' no existe en la configuración."
    fi
    read -p "Enter para continuar..."
}

listar_dominios_dns() {
    log_aviso "--- DOMINIOS ACTIVOS ---"
    preparar_archivo_zonas

    mapfile -t dominios < <(grep "^zone" "$ZONAS_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "${#dominios[@]}" -eq 0 ]]; then
        log_aviso "No hay dominios configurados aún."
        read -p "Enter para continuar..."
        return
    fi
    for dominio in "${dominios[@]}"; do
        if [[ -f "/var/named/db.${dominio}" ]]; then
            local ip
            ip=$(awk '/^@[[:space:]]+IN[[:space:]]+A/ {print $NF}' "/var/named/db.${dominio}" 2>/dev/null)
            echo "  $dominio -> ${ip:-Sin IP detectada}"
        else
            echo "  $dominio -> [ARCHIVO DE ZONA NO ENCONTRADO]"
        fi
    done
    read -p "Enter para continuar..."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 2 — ESTADO DE SERVICIOS
# ────────────────────────────────────────────────────────────

verificar_estado_servicios() {
    clear
    log_aviso "--- ESTADO DE LOS SERVICIOS ---"
    for servicio in dhcpd named; do
        if systemctl is-active "$servicio" &>/dev/null; then
            echo "  $servicio : ${GREEN}[CORRIENDO]${NC}"
        else
            echo "  $servicio : ${RED}[DETENIDO/NO INSTALADO]${NC}"
        fi
    done
    read -p "Enter para continuar..."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 3 — SSH
# ────────────────────────────────────────────────────────────

ssh_verificar_instalacion() {
    echo ""
    log_info "=== Verificando SSH Server en Fedora ==="

    if check_package_present "openssh-server"; then
        log_ok "openssh-server está instalado."
    else
        log_err "openssh-server NO está instalado."
    fi

    if systemctl is-enabled --quiet sshd; then
        log_ok "sshd habilitado en el arranque."
    else
        log_warn "sshd NO está habilitado en el arranque."
    fi

    if systemctl is-active --quiet sshd; then
        log_ok "sshd está activo (corriendo)."
    else
        log_warn "sshd está INACTIVO."
    fi

    if firewall-cmd --query-service=ssh -q 2>/dev/null; then
        log_ok "Firewall permite SSH (puerto 22)."
    else
        log_warn "Firewall NO tiene SSH permitido."
    fi

    echo ""
    log_info "IP de esta máquina (Fedora):"
    ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.'
}

ssh_instalar_configurar() {
    echo ""
    log_info "=== Instalando y configurando SSH Server ==="

    if check_package_present "openssh-server"; then
        log_info "openssh-server ya está instalado."
    else
        install_required_package "openssh-server"
        if [[ $? -eq 0 ]]; then
            log_ok "openssh-server instalado correctamente."
        else
            log_err "Falló al instalar openssh-server."
            exit 1
        fi
    fi

    systemctl is-enabled --quiet sshd || { systemctl enable sshd; log_ok "sshd habilitado."; }
    systemctl is-active  --quiet sshd || { systemctl start  sshd; log_ok "sshd iniciado.";  }

    if firewall-cmd --query-service=ssh -q 2>/dev/null; then
        log_info "Firewall ya permite SSH."
    else
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --reload
        log_ok "Regla SSH agregada al firewall."
    fi

    echo ""
    log_ok "SSH listo. Otras VMs pueden conectarse con:"
    log_info "ssh $(whoami)@$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)"
}

ssh_conectarse() {
    echo ""
    log_info "=== Conexión SSH a VM en red interna ==="

    local ip_local
    ip_local=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)
    log_info "Tu IP actual (Fedora): ${CYAN}$ip_local${NC}"
    echo ""

    local server
    server=$(get_valid_ipaddr "IP de la VM destino (ej. 192.168.x.x):")

    log_info "Verificando conectividad con $server ..."
    if ping -c 2 -W 2 "$server" &>/dev/null; then
        log_ok "$server responde. Red interna OK."
    else
        log_warn "$server NO responde al ping."
        read -rp "¿Intentar conectarse de todos modos? (s/n): " resp
        [[ "$resp" != "s" && "$resp" != "S" ]] && return
    fi

    local user
    while true; do
        read -rp "Usuario en $server: " user
        [[ -n "$user" ]] && break
        log_err "El usuario no puede estar vacío."
    done

    echo ""
    log_info "Conectando a ${CYAN}$user@$server${NC} ..."
    echo -e "${YELLOW}(Para cerrar la sesión SSH escribe: exit)${NC}"
    echo ""

    ssh -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=accept-new \
        "$user@$server"

    echo ""
    log_ok "Sesión cerrada. De vuelta en Fedora ($ip_local)."
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 4 — INFO DEL SISTEMA
# ────────────────────────────────────────────────────────────

p1_mostrar_info() {
    echo ""
    log_info "=== Información del sistema ==="
    echo "  Hostname  : $(hostname)"
    echo "  IPs       :$(hostname -I | tr ' ' '\n' | grep -v '^$' | sed 's/^/    /')"
    echo ""
    log_info "Espacio en disco:"
    df -h
    echo ""
    read -p "Presione Enter..."
}
