#!/bin/bash
# ============================================================
# practica4.sh — SSH Manager (Fedora Server)
# Gestiona SSH local y conexión a VMs en red interna
# Uso: sudo bash practica4.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[OK]${NC}    $1"; }
log_info() { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }

# ════════════════════════════════════════════════════════════
# FUNCIONES UTILITARIAS
# ════════════════════════════════════════════════════════════

verificar_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "Este script debe ejecutarse como root."
        log_info "Usa: sudo bash $0"
        exit 1
    fi
}

check_package_present() {
    rpm -q "$1" &>/dev/null
}

install_required_package() {
    log_info "Instalando paquete: $1 ..."
    dnf install -y "$1" &>/dev/null
    return $?
}

validar_ip() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ $ip =~ $regex ]]; then
        IFS='.' read -r -a octetos <<< "$ip"
        for oct in "${octetos[@]}"; do
            [[ $oct -gt 255 ]] && return 1
        done
        return 0
    fi
    return 1
}

get_valid_ipaddr() {
    local prompt="$1"
    local ip
    while true; do
        read -rp "$prompt " ip
        if validar_ip "$ip"; then
            echo "$ip"
            return 0
        fi
        log_err "IP inválida: '$ip'. Intenta de nuevo."
    done
}

# ════════════════════════════════════════════════════════════
# OPCIÓN 1 — VERIFICAR INSTALACIÓN LOCAL
# ════════════════════════════════════════════════════════════

verificar_instalacion() {
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

# ════════════════════════════════════════════════════════════
# OPCIÓN 2 — INSTALAR Y CONFIGURAR SSH LOCAL
# ════════════════════════════════════════════════════════════

instalar_dependencias() {
    echo ""
    log_info "=== Instalando y configurando SSH Server ==="

    if check_package_present "openssh-server"; then
        log_info "openssh-server ya está instalado."
    else
        install_required_package "openssh-server"
        if [[ $? -eq 0 ]]; then
            log_ok "openssh-server instalado correctamente."
        else
            log_err "Fallo al instalar openssh-server."
            exit 1
        fi
    fi

    if systemctl is-enabled --quiet sshd; then
        log_info "sshd ya está habilitado en el arranque."
    else
        systemctl enable sshd
        log_ok "sshd habilitado en el arranque."
    fi

    if systemctl is-active --quiet sshd; then
        log_info "sshd ya está corriendo."
    else
        systemctl start sshd
        log_ok "sshd iniciado."
    fi

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

# ════════════════════════════════════════════════════════════
# OPCIÓN 3 — CONECTARSE A UNA VM EN LA RED INTERNA
# ════════════════════════════════════════════════════════════

conectarse_ssh() {
    echo ""
    log_info "=== Conexión SSH a VM en red interna ==="

    # Mostrar IP local como referencia
    local ip_local
    ip_local=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)
    log_info "Tu IP actual (Fedora): ${CYAN}$ip_local${NC}"
    echo ""

    # Pedir IP destino
    local server
    server=$(get_valid_ipaddr "IP de la VM destino (ej. 192.168.x.x):")

    # Verificar conectividad antes de intentar SSH
    log_info "Verificando conectividad con $server ..."
    if ping -c 2 -W 2 "$server" &>/dev/null; then
        log_ok "$server responde. Red interna OK."
    else
        log_warn "$server NO responde al ping."
        read -rp "¿Intentar conectarse de todos modos? (s/n): " resp
        [[ "$resp" != "s" && "$resp" != "S" ]] && return
    fi

    # Pedir usuario
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

    # -o ConnectTimeout      → no espera eternamente si la VM no responde
    # -o StrictHostKeyChecking=accept-new → acepta el fingerprint automáticamente
    #                                        la primera vez (no pregunta yes/no)
    ssh -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=accept-new \
        "$user@$server"

    echo ""
    log_ok "Sesión cerrada. De vuelta en Fedora ($ip_local)."
}

# ════════════════════════════════════════════════════════════
# MENÚ PRINCIPAL
# ════════════════════════════════════════════════════════════

mostrar_menu() {
   
    echo " 1) Verificar instalación SSH local"
    echo " 2) Instalar y configurar SSH local"
    echo " 3) Conectarse a una VM en red interna"
    echo " 4) Salir"
   
}

menu_interactivo() {
    while true; do
        mostrar_menu
        read -rp "Selecciona una opción: " opcion
        case $opcion in
            1) verificar_instalacion ;;
            2) instalar_dependencias ;;
            3) conectarse_ssh        ;;
            4) echo "Saliendo..."; exit 0 ;;
            *) log_warn "Opción inválida." ;;
        esac
    done
}

# ════════════════════════════════════════════════════════════
# ENTRADA
# ════════════════════════════════════════════════════════════

verificar_root
menu_interactivo
