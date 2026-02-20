#!/bin/bash

CONF="/etc/named.conf"
ZONE_DIR="/var/named"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

validar_ip() {
    local ip=$1
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    [[ ! $ip =~ $regex ]] && return 1
    IFS='.' read -r -a octs <<< "$ip"
    for o in "${octs[@]}"; do
        [[ $o -lt 0 || $o -gt 255 ]] && return 1
    done
    return 0
}

#ELIMINAR DOMINIOS
opcion_borrar() {
    echo "__________________________________________"

    mapfile -t DOMINIOS < <(grep 'zone "' "$CONF" | awk '{print $2}' | tr -d '"' | grep -v '^\.$\|^0\.\|^1\.\|^2\.')

    if [[ ${#DOMINIOS[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No hay dominios para eliminar.${NC}"
        read -p "Enter para continuar..."
        return
    fi

    echo "Dominios configurados:"
    echo ""
    for i in "${!DOMINIOS[@]}"; do
        echo "  $((i+1))) ${DOMINIOS[$i]}"
    done
    echo "  0) Cancelar"
    echo ""

    while true; do
        read -p "Selecciona dominio: " SEL

        if [[ "$SEL" == "0" ]]; then
            echo "Operacion cancelada"
            return
        fi

        if [[ "$SEL" =~ ^[0-9]+$ ]] && ((SEL>=1 && SEL<=${#DOMINIOS[@]})); then
            break
        fi

        echo -e "${RED}Opcion invalida${NC}"
    done

    ZONA="${DOMINIOS[$((SEL-1))]}"
    ARCHIVO_ZONA="$ZONE_DIR/${ZONA}.zone"

    echo ""
    echo -e "Eliminar dominio: ${YELLOW}$ZONA${NC}"
    read -p "Confirmar (s/n): " CONFIRM

    [[ "$CONFIRM" != "s" && "$CONFIRM" != "S" ]] && {
        echo "Cancelado"
        return
    }

    sudo cp "$CONF" "${CONF}.bak"

    sudo awk '
        /zone "'"$ZONA"'"/ { dentro=1; prof=0 }
        dentro {
            prof += gsub(/{/, "{")
            prof -= gsub(/}/, "}")
            if (prof <= 0) { dentro=0 }
            next
        }
        { print }
    ' "$CONF" > /tmp/named_tmp.conf && sudo mv /tmp/named_tmp.conf "$CONF"

    if [[ -f "$ARCHIVO_ZONA" ]]; then
        sudo rm -f "$ARCHIVO_ZONA"
        echo "Archivo de zona eliminado"
    fi

    if sudo named-checkconf &>/dev/null; then
        sudo systemctl restart named
        echo -e "${GREEN}Dominio eliminado correctamente${NC}"
    else
        echo -e "${RED}Error en configuracion, restaurando respaldo${NC}"
        sudo cp "${CONF}.bak" "$CONF"
        sudo systemctl restart named
    fi

    read -p "Enter para continuar..."
}

# =========================================
# VERIFICAR INSTALACION
# =========================================
opcion_verificar() {
    echo "__________________________________________"
    echo "Verificando instalacion DNS..."

    if rpm -q bind &>/dev/null; then
        echo -e "${GREEN}BIND instalado.${NC}"
        systemctl is-active named
        systemctl status named --no-pager | head -15
    else
        echo -e "${RED}BIND NO instalado.${NC}"
    fi

    read -p "Enter para continuar..."
}

# =========================================
# INSTALAR DNS EN FEDORA
# =========================================
opcion_instalar() {
    echo "__________________________________________"

    if ! rpm -q bind &>/dev/null; then
        echo "Instalando BIND en Fedora..."
        sudo dnf install -y bind bind-utils &>/dev/null
        sudo systemctl enable named &>/dev/null
    else
        echo -e "${YELLOW}BIND ya instalado.${NC}"
    fi

    echo "Configurando named para aceptar consultas externas..."

    sudo sed -i 's/listen-on port 53 { 127.0.0.1; };/listen-on port 53 { any; };/' "$CONF"
    sudo sed -i 's/allow-query.*;/allow-query { any; };/' "$CONF"

    # Abrir DNS en firewall de Fedora
    if systemctl is-active firewalld &>/dev/null; then
        sudo firewall-cmd --permanent --add-service=dns &>/dev/null
        sudo firewall-cmd --reload &>/dev/null
    fi

    sudo systemctl restart named

    if systemctl is-active named &>/dev/null; then
        echo -e "${GREEN}DNS listo en Fedora Server.${NC}"
    else
        echo -e "${RED}named no pudo iniciar → journalctl -xe${NC}"
    fi

    read -p "Enter para continuar..."
}

# =========================================
# AGREGAR DOMINIO
# =========================================
opcion_agregar() {
    echo "+++++++++++++++++++++++++++++++++++++"
    echo "        AGREGAR DOMINIO DNS"
    echo "+++++++++++++++++++++++++++++++++++++"

    read -p "Dominio (ej: empresa.local): " ZONA
    [[ -z "$ZONA" ]] && return

    while true; do
        read -p "IP del servidor: " IP_CLIENTE
        validar_ip "$IP_CLIENTE" && break
        echo -e "${RED}IP invalida${NC}"
    done

    ARCHIVO_ZONA="$ZONE_DIR/${ZONA}.zone"
    SERIAL=$(date +%Y%m%d01)

    if grep -q "zone \"$ZONA\"" "$CONF"; then
        echo -e "${YELLOW}El dominio ya existe${NC}"
        return
    fi

    sudo tee -a "$CONF" > /dev/null <<EOF

zone "$ZONA" IN {
    type master;
    file "${ZONA}.zone";
    allow-update { none; };
};
EOF

    sudo tee "$ARCHIVO_ZONA" > /dev/null <<EOF
\$TTL 86400
@   IN  SOA ns1.$ZONA. admin.$ZONA. (
            $SERIAL
            3600
            1800
            604800
            86400 )
@       IN  NS      ns1.$ZONA.
ns1     IN  A       $IP_CLIENTE
@       IN  A       $IP_CLIENTE
www     IN  A       $IP_CLIENTE
EOF

    # Permisos Fedora + SELinux
    sudo chown root:named "$ARCHIVO_ZONA"
    sudo chmod 640 "$ARCHIVO_ZONA"
    sudo restorecon -v "$ARCHIVO_ZONA" &>/dev/null

    sudo named-checkconf || { echo "Error en named.conf"; return; }
    sudo named-checkzone "$ZONA" "$ARCHIVO_ZONA" || { echo "Error en zona"; return; }

    sudo systemctl restart named
    echo -e "${GREEN}Dominio agregado correctamente${NC}"

    read -p "Enter para continuar..."
}

# =========================================
# VER DOMINIOS
# =========================================
opcion_ver() {
    echo "Dominios configurados:"
    grep 'zone "' "$CONF" | awk '{print $2}' | tr -d '"' | grep -v '^\.$\|^0\.\|^1\.\|^2\.'
    read -p "Enter para continuar..."
}

# =========================================
# MENU
# =========================================
while true; do
    echo -e "\n++++++++ DNS FEDORA SERVER ++++++++"
    echo "1) Verificar instalacion"
    echo "2) Instalar DNS"
    echo "3) Agregar dominio"
    echo "4) Eliminar dominio"
    echo "5) Ver dominios"
    echo "6) Salir"
    read -p "Opcion: " OPT

  case $OPT in
    1) opcion_verificar ;;
    2) opcion_instalar ;;
    3) opcion_agregar ;;
    4) opcion_borrar ;;
    5) opcion_ver ;;
    6) exit ;;
    *) echo "Opcion invalida" ;;
	esac
done
