#!/bin/bash

BASE="/srv/ftp"
FSTAB="/etc/fstab"
export PATH=$PATH:/usr/sbin:/sbin:/usr/bin:/bin

function inicializar_sistema() {
    echo "[+] Instalando dependencias en Fedora..."
    dnf install -y vsftpd util-linux acl &>/dev/null

    echo "[+] Escribiendo configuracion de vsftpd..."
    {
        echo "anonymous_enable=YES"
        echo "local_enable=YES"
        echo "write_enable=YES"
        echo "local_umask=022"
        echo "anon_root=/srv/ftp/anonymous"
        echo "no_anon_password=YES"
        echo "anon_world_readable_only=YES"
        echo "anon_upload_enable=NO"
        echo "anon_mkdir_write_enable=NO"
        echo "anon_other_write_enable=NO"
        echo "chroot_local_user=YES"
        echo "allow_writeable_chroot=YES"
        echo "check_shell=NO"
        echo "pasv_min_port=40000"
        echo "pasv_max_port=40010"
        echo "listen=NO"
        echo "listen_ipv6=YES"
        echo "pam_service_name=vsftpd"
    } > /etc/vsftpd/vsftpd.conf

    echo "[+] Preparando estructura de directorios..."
    mkdir -p \
        "$BASE/general" \
        "$BASE/groups/reprobados" \
        "$BASE/groups/recursadores" \
        "$BASE/anonymous/general" \
        "$BASE/users"

    if [ ! -f "$BASE/general/LEEME.txt" ]; then
        echo "Bienvenido al servidor FTP Publico" > "$BASE/general/LEEME.txt"
    fi

    if ! mountpoint -q "$BASE/anonymous/general"; then
        mount --bind "$BASE/general" "$BASE/anonymous/general"
        mount -o remount,ro,bind "$BASE/anonymous/general"
    fi

    grep -q "$BASE/anonymous/general" "$FSTAB" || \
        echo "$BASE/general  $BASE/anonymous/general  none  bind,ro  0  0" >> "$FSTAB"

    for g in reprobados recursadores ftp-users; do
        groupadd -f "$g"
    done

    chown root:ftp-users "$BASE/general"
    chmod 775 "$BASE/general"
    setfacl -R  -m g:ftp-users:rwx "$BASE/general"
    setfacl -R -dm g:ftp-users:rwx "$BASE/general"

    chgrp reprobados  "$BASE/groups/reprobados"
    chgrp recursadores "$BASE/groups/recursadores"
    chmod 770 "$BASE/groups/reprobados" "$BASE/groups/recursadores"
    setfacl -R  -m g:reprobados:rwx   "$BASE/groups/reprobados"
    setfacl -R -dm g:reprobados:rwx   "$BASE/groups/reprobados"
    setfacl -R  -m g:recursadores:rwx  "$BASE/groups/recursadores"
    setfacl -R -dm g:recursadores:rwx  "$BASE/groups/recursadores"

    configurar_seguridad_ftp

    systemctl enable --now vsftpd &>/dev/null
    systemctl restart vsftpd

    echo "[OK] Sistema inicializado y listo."
}

function configurar_seguridad_ftp() {
    echo "[+] Configurando Firewall..."
    firewall-cmd --permanent --add-service=ftp          &>/dev/null
    firewall-cmd --permanent --add-port=40000-40010/tcp &>/dev/null
    firewall-cmd --reload                               &>/dev/null

    echo "[+] Ajustando SELinux..."
    setsebool -P ftpd_full_access on &>/dev/null
    setsebool -P tftp_home_dir    on &>/dev/null

    grep -q "/sbin/nologin" /etc/shells || echo "/sbin/nologin" >> /etc/shells

    echo "[OK] Firewall y SELinux configurados."
}

function _configurar_montajes() {
    local user="$1"
    local group="$2"
    local home="/home/$user"

    mkdir -p "$home/general" "$home/$group"

    for dir in general reprobados recursadores; do
        mountpoint -q "$home/$dir" && umount -l "$home/$dir" 2>/dev/null
    done

    mount --bind "$BASE/general"        "$home/general"
    mount --bind "$BASE/groups/$group"  "$home/$group"

    grep -q "$home/general" "$FSTAB" || \
        echo "$BASE/general         $home/general  none  bind  0  0" >> "$FSTAB"
    grep -q "$home/$group"  "$FSTAB" || \
        echo "$BASE/groups/$group  $home/$group  none  bind  0  0"   >> "$FSTAB"
}

function _aplicar_permisos_personales() {
    local user="$1"
    local group="$2"
    local home="/home/$user"

    chown "$user:$group" "$home/$user"
    chmod 700 "$home/$user"

    setfacl -R  -m g:"$group":rwx "$BASE/groups/$group"
    setfacl -R -dm g:"$group":rwx "$BASE/groups/$group"
}

function crear_usuario() {
    local user="$1"
    local pass="$2"
    local group="$3"

    if id "$user" &>/dev/null; then
        echo "[!] El usuario $user ya existe. Saltando..."
        return
    fi

    useradd -m -g ftp-users -G "$group" -s /sbin/nologin "$user"
    echo "$user:$pass" | chpasswd

    local home="/home/$user"
    chown root:root "$home"
    chmod 555 "$home"

    mkdir -p "$home/general" "$home/$group" "$home/$user"

    _configurar_montajes "$user" "$group"
    _aplicar_permisos_personales "$user" "$group"

    echo "[OK] Usuario $user creado en grupo $group."
}

function crear_usuarios_masivo() {
    clear
    echo "[*] Creacion Masiva de Usuarios"
    read -p "Cantidad de usuarios a crear: " N

    for (( i=1; i<=N; i++ )); do
        echo ""
        echo "--- Usuario $i de $N ---"
        read -p "Nombre de usuario: " nombre
        read -s -p "Contrasena: " pass
        echo ""
        echo "Grupo: 1) reprobados | 2) recursadores"
        read -p "Opcion: " g_opt
        if [[ "$g_opt" == "1" ]]; then
            grupo="reprobados"
        else
            grupo="recursadores"
        fi
        crear_usuario "$nombre" "$pass" "$grupo"
    done
    sleep 1
}

function modificar_grupo_usuario() {
    echo ""
    echo "--- Cambio de Grupo ---"
    read -p "Nombre del usuario: " user

    if ! id "$user" &>/dev/null; then
        echo "[!] El usuario no existe."
        return 1
    fi

    echo "Nuevo grupo: 1) reprobados | 2) recursadores"
    read -p "Opcion: " g_opt

    if [[ "$g_opt" == "1" ]]; then
        nuevo="reprobados"
        viejo="recursadores"
    else
        nuevo="recursadores"
        viejo="reprobados"
    fi

    local home="/home/$user"

    mountpoint -q "$home/$viejo" && umount -l "$home/$viejo"
    rm -rf "$home/$viejo"
    sed -i "\|$home/$viejo|d" "$FSTAB"

    usermod -g ftp-users -G "$nuevo" "$user"

    mkdir -p "$home/$nuevo"
    mount --bind "$BASE/groups/$nuevo" "$home/$nuevo"
    grep -q "$home/$nuevo" "$FSTAB" || \
        echo "$BASE/groups/$nuevo  $home/$nuevo  none  bind  0  0" >> "$FSTAB"

    _aplicar_permisos_personales "$user" "$nuevo"

    echo "[OK] $user movido al grupo $nuevo."
}

function listar_usuarios_ftp() {
    echo ""
    echo "--- [ USUARIOS REGISTRADOS EN FTP ] ---"
    printf "%-20s | %-20s\n" "USUARIO" "GRUPO ACADEMICO"
    echo "------------------------------------------------"

    local ftp_gid
    ftp_gid=$(getent group ftp-users | cut -d: -f3)

    if [ -z "$ftp_gid" ]; then
        echo "Grupo ftp-users no encontrado."
        return
    fi

    local members
    members=$(awk -F: -v gid="$ftp_gid" '$4 == gid {print $1}' /etc/passwd)

    if [ -z "$members" ]; then
        echo "No hay usuarios registrados aun."
    else
        while IFS= read -r u; do
            if id "$u" 2>/dev/null | grep -q "reprobados"; then
                gr="reprobados"
            elif id "$u" 2>/dev/null | grep -q "recursadores"; then
                gr="recursadores"
            else
                gr="Sin grupo academico"
            fi
            printf "%-20s | %-20s\n" "$u" "$gr"
        done <<< "$members"
    fi
    echo "------------------------------------------------"
}

function verificar_servicio_ftp() {
    echo ""
    echo "--- [ DIAGNOSTICO DEL SERVICIO FTP ] ---"

    if systemctl is-active --quiet vsftpd; then
        echo -e "Estado vsftpd         : \e[32m[ EN EJECUCION ]\e[0m"
    else
        echo -e "Estado vsftpd         : \e[31m[ DETENIDO ]\e[0m"
    fi

    echo -n "Puertos activos       : "
    ss -tunlp 2>/dev/null | grep -E '(:21|:4000[0-9]|:40010)' | awk '{print $5}' | tr '\n' ' '
    echo ""

    echo -n "Montaje anonimo       : "
    if mountpoint -q "$BASE/anonymous/general"; then
        echo -e "\e[32m[ OK ]\e[0m"
    else
        echo -e "\e[31m[ NO MONTADO ]\e[0m"
    fi

    echo -n "IP del servidor       : "
    IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [ -n "$IP" ]; then
        echo -e "\e[34m$IP\e[0m"
    else
        echo -e "\e[31m[ No detectada ]\e[0m"
    fi

    echo -n "SELinux ftpd_full_access: "
    getsebool ftpd_full_access 2>/dev/null | grep -q "on" \
        && echo -e "\e[32m[ ON ]\e[0m" \
        || echo -e "\e[31m[ OFF ]\e[0m"

    echo -n "Firewall FTP          : "
    firewall-cmd --list-services 2>/dev/null | grep -q "ftp" \
        && echo -e "\e[32m[ PERMITIDO ]\e[0m" \
        || echo -e "\e[31m[ BLOQUEADO ]\e[0m"

    echo "Conexiones FTP activas: $(ss -tnp 2>/dev/null | grep -c ':21' || echo 0)"
    echo "------------------------------------------------"
}

function menu_usuarios() {
    while true; do
        echo ""
        echo "[*] Gestion de Usuarios y Grupos"
        echo "1) Crear Usuarios (Masivo)"
        echo "2) Cambiar Grupo de Usuario"
        echo "3) Listar Usuarios FTP"
        echo "7) Volver"
        read -p "Opcion: " op
        case $op in
            1) crear_usuarios_masivo ;;
            2) modificar_grupo_usuario ;;
            3) listar_usuarios_ftp ;;
            7) return ;;
            *) echo "Opcion no valida." ;;
        esac
    done
}

function menu_principal() {
    while true; do
        echo ""
        echo "========================================"
        echo "    Administrador FTP - Fedora (vsftpd) "
        echo "========================================"
        echo "1) Inicializar sistema"
        echo "2) Gestion de Usuarios"
        echo "3) Diagnostico del servicio"
        echo "4) Ver estado de vsftpd"
        echo "5) Reiniciar vsftpd"
        echo "6) Salir"
        read -p "Opcion: " op
        case $op in
            1) inicializar_sistema ;;
            2) menu_usuarios ;;
            3) verificar_servicio_ftp ;;
            4) systemctl status vsftpd --no-pager ;;
            5) systemctl restart vsftpd && echo "[OK] vsftpd reiniciado." ;;
            6) echo "Saliendo..."; exit 0 ;;
            *) echo "Opcion no valida." ;;
        esac
    done
}

if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] Ejecutar como root: sudo bash $0"
    exit 1
fi

menu_principal
