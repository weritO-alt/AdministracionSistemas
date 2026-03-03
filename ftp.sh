#!/bin/bash
# ================================================================
# ADMINISTRADOR FTP ROBUSTO - FEDORA SERVER (vsftpd)
# ================================================================

# --- COLORES ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# --- LOG ---
LOG_PATH="/var/log/admin_ftp.log"

write_log() {
    local MENSAJE="$1"
    local NIVEL="${2:-INFO}"
    local TIMESTAMP
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    local LINEA="[$TIMESTAMP] [$NIVEL] $MENSAJE"
    echo "$LINEA" >> "$LOG_PATH"
    case "$NIVEL" in
        "ERROR")   echo -e "${RED}${LINEA}${NC}" ;;
        "WARNING") echo -e "${YELLOW}${LINEA}${NC}" ;;
        "OK")      echo -e "${GREEN}${LINEA}${NC}" ;;
        *)         echo -e "${CYAN}${LINEA}${NC}" ;;
    esac
}

# ================================================================
# 0. VERIFICAR ROOT
# ================================================================
verificar_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Este script debe ejecutarse como root (sudo).${NC}"
        exit 1
    fi
}

# ================================================================
# 1. INSTALACIÓN E IDEMPOTENCIA DEL SERVICIO
# ================================================================
setup_entorno() {
    # Instalar vsftpd si no está instalado
    if ! rpm -q vsftpd &>/dev/null; then
        write_log "Instalando vsftpd..." "INFO"
        dnf install -y vsftpd &>/dev/null
        write_log "vsftpd instalado." "OK"
    else
        write_log "vsftpd ya está instalado, omitiendo." "INFO"
    fi

    # Estructura de directorios
    local RUTAS=(
        "/srv/ftp/general"
        "/srv/ftp/grupos/reprobados"
        "/srv/ftp/grupos/recursadores"
    )
    for RUTA in "${RUTAS[@]}"; do
        if [[ ! -d "$RUTA" ]]; then
            mkdir -p "$RUTA"
            write_log "Directorio creado: $RUTA" "INFO"
        fi
    done

    # Grupos del sistema
    for GRUPO in reprobados recursadores; do
        if ! getent group "$GRUPO" &>/dev/null; then
            groupadd "$GRUPO"
            write_log "Grupo '$GRUPO' creado." "OK"
        fi
    done

    # Permisos carpeta general (todos pueden escribir, anónimo solo lee)
    chown root:root /srv/ftp/general
    chmod 755 /srv/ftp/general

    # Permisos carpetas de grupo (escritura para miembros del grupo)
    for GRUPO in reprobados recursadores; do
        chown root:"$GRUPO" "/srv/ftp/grupos/$GRUPO"
        chmod 775 "/srv/ftp/grupos/$GRUPO"
    done

    # ---- CONFIGURAR vsftpd.conf ----
    local CONF="/etc/vsftpd/vsftpd.conf"
    cp "$CONF" "${CONF}.bak" 2>/dev/null

    cat > "$CONF" << 'EOF'
# ---- Configuración base ----
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_std_format=YES
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
userlist_enable=YES
userlist_deny=NO
userlist_file=/etc/vsftpd/user_list

# ---- Acceso anónimo (solo lectura en /general) ----
anon_root=/srv/ftp
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO

# ---- Usuarios locales ----
local_root=/srv/ftp/users/$USER
EOF

    # Lista de usuarios permitidos (vacía al inicio, se llena al crear usuarios)
    touch /etc/vsftpd/user_list

    # Agregar ftp_anonymous a la lista si no existe
    if ! grep -q "^ftp$" /etc/vsftpd/user_list 2>/dev/null; then
        echo "ftp" >> /etc/vsftpd/user_list
    fi

    # Firewall: abrir puerto 21
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-service=ftp &>/dev/null
        firewall-cmd --reload &>/dev/null
        write_log "Puerto FTP abierto en firewall." "OK"
    fi

    # SELinux: permitir vsftpd con home dirs
    if command -v setsebool &>/dev/null; then
        setsebool -P ftpd_full_access on &>/dev/null
        setsebool -P allow_ftpd_full_access on &>/dev/null
        write_log "SELinux configurado para vsftpd." "OK"
    fi

    # Habilitar e iniciar vsftpd
    systemctl enable vsftpd &>/dev/null
    systemctl restart vsftpd

    write_log "Entorno Fedora FTP configurado completamente." "OK"
}

# ================================================================
# VALIDAR CONTRASEÑA
# ================================================================
validar_contra() {
    local PASS="$1"
    local LEN=${#PASS}
    if [[ $LEN -lt 8 || $LEN -gt 15 ]];                    then return 1; fi
    if ! echo "$PASS" | grep -q '[A-Z]';                    then return 1; fi
    if ! echo "$PASS" | grep -q '[a-z]';                    then return 1; fi
    if ! echo "$PASS" | grep -q '[0-9]';                    then return 1; fi
    if ! echo "$PASS" | grep -q '[^a-zA-Z0-9]';             then return 1; fi
    return 0
}

# ================================================================
# FUNCIÓN BASE: CREAR UN USUARIO
# ================================================================
crear_usuario() {
    local USER="$1"
    local PASS="$2"
    local GRUPO="$3"

    # Crear usuario del sistema sin shell de login
    useradd -M -s /sbin/nologin "$USER"
    echo "$USER:$PASS" | chpasswd

    # Agregar al grupo FTP correspondiente
    usermod -aG "$GRUPO" "$USER"

    # ---- Estructura de directorios ----
    # El usuario ve esto al conectarse: general / grupo / su_nombre
    local USER_ROOT="/srv/ftp/users/$USER"
    mkdir -p "$USER_ROOT/$USER"
    mkdir -p "$USER_ROOT/general"
    mkdir -p "$USER_ROOT/$GRUPO"

    # ---- Permisos carpeta personal (solo el usuario) ----
    chown "$USER":"$USER" "$USER_ROOT/$USER"
    chmod 700 "$USER_ROOT/$USER"

    # ---- Enlace simbólico a /general (escritura para autenticados) ----
    # Montar la carpeta general dentro del chroot del usuario
    mount --bind /srv/ftp/general "$USER_ROOT/general" 2>/dev/null || \
        ln -sfn /srv/ftp/general "$USER_ROOT/general"

    # ---- Enlace simbólico a carpeta de grupo ----
    mount --bind "/srv/ftp/grupos/$GRUPO" "$USER_ROOT/$GRUPO" 2>/dev/null || \
        ln -sfn "/srv/ftp/grupos/$GRUPO" "$USER_ROOT/$GRUPO"

    # ---- Permisos en /general para usuarios autenticados ----
    setfacl -m "u:$USER:rwx" /srv/ftp/general
    setfacl -d -m "u:$USER:rwx" /srv/ftp/general

    # ---- Permisos en carpeta de grupo ----
    setfacl -m "u:$USER:rwx" "/srv/ftp/grupos/$GRUPO"
    setfacl -d -m "u:$USER:rwx" "/srv/ftp/grupos/$GRUPO"

    # Raíz del chroot debe ser propiedad de root
    chown root:root "$USER_ROOT"
    chmod 755 "$USER_ROOT"

    # Agregar a la lista de usuarios permitidos en vsftpd
    if ! grep -q "^$USER$" /etc/vsftpd/user_list; then
        echo "$USER" >> /etc/vsftpd/user_list
    fi

    write_log "Usuario '$USER' creado en grupo '$GRUPO'." "OK"
}

# ================================================================
# 2. MENÚ → CREAR UN USUARIO
# ================================================================
crear_usuario_menu() {
    read -rp "Nombre de usuario: " USER
    USER=$(echo "$USER" | tr -d '[:space:]')

    if [[ -z "$USER" ]]; then
        write_log "Nombre de usuario vacío." "WARNING"; return
    fi
    if id "$USER" &>/dev/null; then
        write_log "El usuario '$USER' ya existe." "WARNING"; return
    fi

    read -rsp "Contraseña (8-15 carac, Mayus, Minus, Num, Especial): " PASS; echo
    if ! validar_contra "$PASS"; then
        write_log "La contraseña no cumple los requisitos de seguridad." "ERROR"; return
    fi

    echo "Grupo: 1) Reprobados  2) Recursadores"
    read -rp "Seleccione grupo: " G_OPT
    if [[ "$G_OPT" == "1" ]]; then GRUPO="reprobados"
    elif [[ "$G_OPT" == "2" ]]; then GRUPO="recursadores"
    else
        write_log "Opción de grupo inválida." "WARNING"; return
    fi

    crear_usuario "$USER" "$PASS" "$GRUPO"
}

# ================================================================
# 3. CREACIÓN MASIVA DE USUARIOS
# ================================================================
crear_usuarios_masivo() {
    read -rp "¿Cuántos usuarios desea crear? " N
    if ! [[ "$N" =~ ^[0-9]+$ ]] || [[ "$N" -le 0 ]]; then
        write_log "Número inválido." "WARNING"; return
    fi

    for ((i=1; i<=N; i++)); do
        echo -e "\n${CYAN}--- Usuario $i de $N ---${NC}"

        read -rp "  Nombre de usuario: " USER
        USER=$(echo "$USER" | tr -d '[:space:]')

        if [[ -z "$USER" ]]; then
            write_log "Nombre vacío, saltando usuario $i." "WARNING"; continue
        fi
        if id "$USER" &>/dev/null; then
            write_log "El usuario '$USER' ya existe, saltando." "WARNING"; continue
        fi

        read -rsp "  Contraseña (8-15 carac, Mayus, Minus, Num, Especial): " PASS; echo
        if ! validar_contra "$PASS"; then
            write_log "Contraseña inválida para '$USER', saltando." "ERROR"; continue
        fi

        echo "  Grupo: 1) Reprobados  2) Recursadores"
        read -rp "  Seleccione grupo: " G_OPT
        if [[ "$G_OPT" == "1" ]]; then GRUPO="reprobados"
        elif [[ "$G_OPT" == "2" ]]; then GRUPO="recursadores"
        else
            write_log "Grupo inválido para '$USER', saltando." "WARNING"; continue
        fi

        crear_usuario "$USER" "$PASS" "$GRUPO"
    done

    write_log "Creación masiva finalizada ($N usuarios procesados)." "OK"
}

# ================================================================
# 4. CAMBIAR GRUPO FTP
# ================================================================
cambiar_grupo() {
    read -rp "Nombre de usuario a cambiar de grupo: " USER
    USER=$(echo "$USER" | tr -d '[:space:]')

    if ! id "$USER" &>/dev/null; then
        write_log "El usuario '$USER' no existe." "WARNING"; return
    fi

    # Detectar grupo actual
    GRUPO_ACTUAL=""
    for G in reprobados recursadores; do
        if id -nG "$USER" | grep -qw "$G"; then
            GRUPO_ACTUAL="$G"
        fi
    done

    if [[ -z "$GRUPO_ACTUAL" ]]; then
        write_log "No se encontró '$USER' en ningún grupo FTP." "WARNING"; return
    fi

    GRUPO_NUEVO=$([ "$GRUPO_ACTUAL" == "reprobados" ] && echo "recursadores" || echo "reprobados")

    read -rp "El usuario '$USER' está en '$GRUPO_ACTUAL'. ¿Mover a '$GRUPO_NUEVO'? (s/N): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Ss]$ ]]; then
        write_log "Operación cancelada." "INFO"; return
    fi

    # Cambiar grupo
    gpasswd -d "$USER" "$GRUPO_ACTUAL" &>/dev/null
    usermod -aG "$GRUPO_NUEVO" "$USER"

    local USER_ROOT="/srv/ftp/users/$USER"

    # Quitar ACL del grupo anterior
    setfacl -x "u:$USER" "/srv/ftp/grupos/$GRUPO_ACTUAL" 2>/dev/null

    # Asignar ACL en nuevo grupo
    setfacl -m "u:$USER:rwx" "/srv/ftp/grupos/$GRUPO_NUEVO"
    setfacl -d -m "u:$USER:rwx" "/srv/ftp/grupos/$GRUPO_NUEVO"

    # Actualizar enlace/bind del directorio de grupo
    umount "$USER_ROOT/$GRUPO_ACTUAL" 2>/dev/null
    rm -rf "$USER_ROOT/$GRUPO_ACTUAL"
    mkdir -p "$USER_ROOT/$GRUPO_NUEVO"
    mount --bind "/srv/ftp/grupos/$GRUPO_NUEVO" "$USER_ROOT/$GRUPO_NUEVO" 2>/dev/null || \
        ln -sfn "/srv/ftp/grupos/$GRUPO_NUEVO" "$USER_ROOT/$GRUPO_NUEVO"

    chown root:root "$USER_ROOT"
    chmod 755 "$USER_ROOT"

    write_log "Usuario '$USER' movido de '$GRUPO_ACTUAL' a '$GRUPO_NUEVO'." "OK"
}

# ================================================================
# 5. ELIMINAR USUARIO FTP
# ================================================================
eliminar_usuario() {
    read -rp "Nombre de usuario a eliminar: " USER
    USER=$(echo "$USER" | tr -d '[:space:]')

    if ! id "$USER" &>/dev/null; then
        write_log "El usuario '$USER' no existe." "WARNING"; return
    fi

    echo -e "${RED}ADVERTENCIA: Se eliminará '$USER' y todos sus archivos.${NC}"
    read -rp "Escriba el nombre del usuario para confirmar: " CONFIRM
    if [[ "$CONFIRM" != "$USER" ]]; then
        write_log "Confirmación incorrecta. Operación cancelada." "WARNING"; return
    fi

    # Desmontar bind mounts si existen
    umount "/srv/ftp/users/$USER/general"      2>/dev/null
    umount "/srv/ftp/users/$USER/reprobados"   2>/dev/null
    umount "/srv/ftp/users/$USER/recursadores" 2>/dev/null

    # Quitar ACLs de carpetas compartidas
    setfacl -x "u:$USER" /srv/ftp/general 2>/dev/null
    setfacl -x "u:$USER" /srv/ftp/grupos/reprobados 2>/dev/null
    setfacl -x "u:$USER" /srv/ftp/grupos/recursadores 2>/dev/null

    # Eliminar de la lista vsftpd
    sed -i "/^$USER$/d" /etc/vsftpd/user_list

    # Eliminar usuario y su directorio
    userdel -r "$USER" 2>/dev/null
    rm -rf "/srv/ftp/users/$USER"

    write_log "Usuario '$USER' eliminado correctamente." "OK"
}

# ================================================================
# 6. LISTAR USUARIOS POR GRUPO
# ================================================================
listar_usuarios() {
    echo -e "\n${CYAN}--- Usuarios FTP por grupo ---${NC}"
    for GRUPO in reprobados recursadores; do
        echo -e "\n${YELLOW}Grupo: $GRUPO${NC}"
        MIEMBROS=$(getent group "$GRUPO" | cut -d: -f4 | tr ',' '\n')
        if [[ -z "$MIEMBROS" ]]; then
            echo "  (sin usuarios)"
        else
            while IFS= read -r M; do echo "  - $M"; done <<< "$MIEMBROS"
        fi
    done
    echo ""
}

# ================================================================
# INICIO DEL SCRIPT
# ================================================================
verificar_root

# Instalar acl si no está (necesario para setfacl)
if ! rpm -q acl &>/dev/null; then
    dnf install -y acl &>/dev/null
fi

setup_entorno

while true; do
    echo -e "\n${CYAN}==========================================${NC}"
    echo -e "${CYAN}     ADMINISTRADOR FTP FEDORA SERVER      ${NC}"
    echo -e "${CYAN}==========================================${NC}"
    echo "1. Crear un Usuario"
    echo "2. Creacion Masiva de Usuarios"
    echo "3. Cambiar Usuario de Grupo"
    echo "4. Eliminar Usuario"
    echo "5. Listar Usuarios por Grupo"
    echo "6. Reiniciar Servicio FTP"
    echo "7. Salir"
    echo "------------------------------------------"
    read -rp "Seleccione una opcion: " OPCION

    case "$OPCION" in
        1) crear_usuario_menu   ;;
        2) crear_usuarios_masivo ;;
        3) cambiar_grupo         ;;
        4) eliminar_usuario      ;;
        5) listar_usuarios       ;;
        6)
            systemctl restart vsftpd
            write_log "Servicio vsftpd reiniciado manualmente." "OK"
            ;;
        7)
            write_log "Sesión cerrada." "INFO"
            exit 0
            ;;
        *)
            echo -e "${YELLOW}Opción no válida.${NC}"
            ;;
    esac
done
