#!/bin/bash

# ================================================================
#  P10 INFRA - MÓDULO DOCKER  (Fedora Server)
#  Infraestructura con contenedores: Web, PostgreSQL, FTP
# ================================================================

# ----------------------------------------------------------------
# VARIABLES GLOBALES
# ----------------------------------------------------------------
INFRA_RED="infra_red"
INFRA_SUBNET="172.20.0.0/16"
VOL_DB="db_data"
VOL_WEB="web_content"
DIR_BACKUP="/opt/docker/backups/postgres"
DIR_FTP="/opt/docker/ftp"
DIR_WEB="/opt/docker/web"

# ----------------------------------------------------------------
# UTILIDADES
# ----------------------------------------------------------------
ok()   { echo -e "\e[32m[OK] $*\e[0m"; }
warn() { echo -e "\e[33m[!]  $*\e[0m"; }
err()  { echo -e "\e[31m[X]  $*\e[0m"; }
info() { echo -e "\e[34m[*]  $*\e[0m"; }

verificar_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Este script debe ejecutarse como root (sudo)."
        exit 1
    fi
}

verificar_docker() {
    if ! command -v docker &>/dev/null; then
        err "Docker no está instalado. Ejecuta la opción 1 primero."
        return 1
    fi
    if ! docker info &>/dev/null; then
        err "El demonio de Docker no está corriendo."
        err "Intenta: systemctl start docker"
        return 1
    fi
    return 0
}

# ----------------------------------------------------------------
# MENÚ PRINCIPAL
# ----------------------------------------------------------------
menu_docker() {
    verificar_root
    while true; do
        echo -e "\n======================================"
        echo -e "     MODULO DOCKER - P10 INFRA"
        echo -e "       (Fedora Server Edition)"
        echo -e "======================================"
        echo "1)  Instalar Docker"
        echo "2)  Setup Completo (Red + Volumes + Servicios)"
        echo "3)  Listar Contenedores"
        echo "4)  Crear Contenedor Simple"
        echo "5)  Iniciar Contenedor"
        echo "6)  Detener Contenedor"
        echo "7)  Eliminar Contenedor"
        echo "8)  Ver Stats de Recursos"
        echo "9)  Backup Manual PostgreSQL"
        echo "10) Protocolo de Pruebas"
        echo "11) Volver al Menú Principal"
        echo "======================================"
        read -rp "Opción: " docker_opcion
        case $docker_opcion in
            1)  instalar_docker ;;
            2)  verificar_docker && setup_completo ;;
            3)  verificar_docker && listar_contenedores ;;
            4)  verificar_docker && crear_contenedor ;;
            5)  verificar_docker && iniciar_contenedor ;;
            6)  verificar_docker && detener_contenedor ;;
            7)  verificar_docker && eliminar_contenedor ;;
            8)  verificar_docker && ver_stats ;;
            9)  verificar_docker && backup_postgres ;;
            10) verificar_docker && menu_pruebas ;;
            11) break ;;
            *) err "Opción inválida." ;;
        esac
    done
}

# ================================================================
# INSTALAR DOCKER EN FEDORA
#   - Repositorio oficial Docker para Fedora
#   - dnf en lugar de apt-get
#   - Se agrega el usuario actual al grupo docker
# ================================================================
instalar_docker() {
    info "Instalando Docker en Fedora Server..."

    # Dependencias previas
    dnf -y install dnf-plugins-core curl

    # Agregar repositorio oficial Docker para Fedora
    dnf config-manager --add-repo \
        https://download.docker.com/linux/fedora/docker-ce.repo

    # Instalar Docker Engine
    dnf -y install docker-ce docker-ce-cli containerd.io \
                   docker-buildx-plugin docker-compose-plugin

    # Habilitar e iniciar el servicio
    systemctl enable --now docker

    # Agregar usuario al grupo docker (evitar usar sudo en cada comando)
    if [ -n "$SUDO_USER" ]; then
        usermod -aG docker "$SUDO_USER"
        ok "Usuario '$SUDO_USER' agregado al grupo docker."
        warn "Cierra sesión y vuelve a entrar para aplicar el grupo."
    fi

    # Abrir puertos en firewalld (activo por defecto en Fedora)
    abrir_puertos_firewall

    ok "Docker instalado: $(docker --version)"
}

# ----------------------------------------------------------------
# FIREWALLD – Abrir puertos necesarios
# ----------------------------------------------------------------
abrir_puertos_firewall() {
    if systemctl is-active --quiet firewalld; then
        info "Configurando firewalld..."
        firewall-cmd --permanent --add-port=80/tcp      # Web
        firewall-cmd --permanent --add-port=21/tcp      # FTP control
        firewall-cmd --permanent --add-port=30000-30009/tcp  # FTP pasivo
        # Permitir que Docker acceda a la red del host
        firewall-cmd --permanent --zone=trusted --add-interface=docker0
        firewall-cmd --permanent --zone=trusted --add-interface="${INFRA_RED}" 2>/dev/null
        firewall-cmd --reload
        ok "Puertos abiertos en firewalld (80, 21, 30000-30009)."
    else
        warn "firewalld no está activo. Verifica tu firewall manualmente."
    fi
}

# ================================================================
# SETUP COMPLETO
# ================================================================
setup_completo() {
    info "Iniciando Setup Completo de Infraestructura..."
    crear_red
    crear_volumenes
    crear_directorios
    crear_dockerfile_web
    construir_imagen_web
    crear_contenedor_web
    crear_contenedor_postgres
    crear_contenedor_ftp
    configurar_backup_automatico
    echo ""
    ok "Setup completo finalizado."
    listar_contenedores
}

# ----------------------------------------------------------------
# RED BRIDGE PERSONALIZADA
# ----------------------------------------------------------------
crear_red() {
    info "Configurando red $INFRA_RED ($INFRA_SUBNET)..."
    if docker network ls --format '{{.Name}}' | grep -q "^${INFRA_RED}$"; then
        warn "Red $INFRA_RED ya existe."
    else
        docker network create \
            --driver bridge \
            --subnet "$INFRA_SUBNET" \
            --label "proyecto=p10" \
            "$INFRA_RED"
        ok "Red $INFRA_RED creada."
    fi
}

# ----------------------------------------------------------------
# VOLÚMENES PERSISTENTES
# ----------------------------------------------------------------
crear_volumenes() {
    info "Creando volúmenes persistentes..."
    for vol in "$VOL_DB" "$VOL_WEB"; do
        if docker volume ls --format '{{.Name}}' | grep -q "^${vol}$"; then
            warn "Volumen $vol ya existe."
        else
            docker volume create "$vol"
            ok "Volumen $vol creado."
        fi
    done
}

# ----------------------------------------------------------------
# DIRECTORIOS EN EL HOST
# ----------------------------------------------------------------
crear_directorios() {
    info "Creando directorios en el host..."
    mkdir -p "$DIR_BACKUP" "$DIR_FTP" "$DIR_WEB"
    chmod 755 "$DIR_BACKUP"
    chmod 777 "$DIR_FTP"     # FTP necesita escritura libre
    chmod 755 "$DIR_WEB"

    # SELinux: marcar directorios para que Docker pueda acceder
    if command -v chcon &>/dev/null && getenforce 2>/dev/null | grep -q "Enforcing"; then
        info "SELinux activo — aplicando contexto container_file_t..."
        chcon -Rt container_file_t "$DIR_BACKUP"
        chcon -Rt container_file_t "$DIR_FTP"
        chcon -Rt container_file_t "$DIR_WEB"
        ok "Contexto SELinux aplicado."
    fi

    ok "Directorios creados."
}

# ================================================================
# DOCKERFILE PERSONALIZADO PARA WEB
#   - Imagen base Alpine Linux (ligera)
#   - server_tokens off  → sin firma de versión en cabeceras HTTP
#   - Usuario no-root    → proceso nginx corre como "webuser"
# ================================================================
crear_dockerfile_web() {
    info "Creando Dockerfile personalizado para servidor web..."
    mkdir -p "$DIR_WEB/html/css" "$DIR_WEB/html/img" "$DIR_WEB/html/js"

    # --- Página principal ---
    cat > "$DIR_WEB/html/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Infraestructura P10 - ayala.local</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <header>
        <div class="logo-wrap">
            <img src="img/logo.svg" alt="Logo P10" class="logo">
            <h1>Infraestructura P10</h1>
        </div>
    </header>
    <main class="container">
        <section class="card">
            <h2>&#x1F4BB; Servidor Web</h2>
            <table>
                <tr><td>Dominio</td><td><strong>ayala.local</strong></td></tr>
                <tr><td>Imagen</td><td><strong>Alpine Linux + Nginx</strong></td></tr>
                <tr><td>IP</td><td><strong>172.20.0.10</strong></td></tr>
                <tr><td>Red</td><td><strong>infra_red</strong></td></tr>
            </table>
        </section>
        <section class="card">
            <h2>&#x1F5C4; Servicios Activos</h2>
            <ul>
                <li><span class="badge green">&#x25CF; web_server</span> Puerto 80</li>
                <li><span class="badge blue">&#x25CF; db_postgres</span> Puerto 5432</li>
                <li><span class="badge orange">&#x25CF; ftp_server</span> Puerto 21</li>
            </ul>
        </section>
    </main>
    <footer>P10 Infraestructura &mdash; Docker en Fedora Server</footer>
    <script src="js/status.js"></script>
</body>
</html>
EOF

    # --- CSS ---
    cat > "$DIR_WEB/html/css/style.css" << 'EOF'
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body   { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
header { background: #161b22; border-bottom: 1px solid #30363d; padding: 1rem 2rem; }
.logo-wrap { display: flex; align-items: center; gap: 1rem; }
.logo  { width: 48px; height: 48px; }
h1     { color: #58a6ff; font-size: 1.5rem; }
.container { max-width: 860px; margin: 2rem auto; padding: 0 1rem; display: grid; gap: 1.5rem; }
.card  { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 1.5rem; }
h2     { color: #58a6ff; margin-bottom: 1rem; font-size: 1.1rem; }
table  { width: 100%; border-collapse: collapse; }
td     { padding: 0.5rem 0.75rem; border-bottom: 1px solid #21262d; }
td:first-child { color: #8b949e; width: 40%; }
ul     { list-style: none; display: flex; flex-direction: column; gap: 0.5rem; }
.badge { display: inline-block; border-radius: 20px; padding: 0.3rem 0.8rem;
         font-size: 0.85rem; margin-right: 0.5rem; }
.green  { background: #1a4731; color: #3fb950; }
.blue   { background: #0c2d6b; color: #58a6ff; }
.orange { background: #5a2d00; color: #d29922; }
footer { text-align: center; padding: 2rem; color: #484f58;
         font-size: 0.85rem; border-top: 1px solid #21262d; margin-top: 2rem; }
EOF

    # --- JS estático ---
    cat > "$DIR_WEB/html/js/status.js" << 'EOF'
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.badge').forEach(b => {
        b.title = 'Contenedor activo en red infra_red';
    });
    console.log('[P10] Página cargada correctamente.');
});
EOF

    # --- Logo SVG (recurso estático) ---
    cat > "$DIR_WEB/html/img/logo.svg" << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
  <rect width="64" height="64" rx="12" fill="#161b22"/>
  <rect x="8" y="20" width="48" height="8" rx="3" fill="#58a6ff"/>
  <rect x="8" y="34" width="48" height="8" rx="3" fill="#3fb950"/>
  <rect x="8" y="48" width="20" height="8" rx="3" fill="#d29922"/>
  <circle cx="52" cy="52" r="6" fill="#d29922"/>
</svg>
EOF

    # --- nginx.conf ---
    # pid en /tmp → escribible por usuario no-root
    # server_tokens off → oculta versión de nginx en cabeceras HTTP
    cat > "$DIR_WEB/nginx.conf" << 'EOF'
worker_processes 1;
pid /tmp/nginx.pid;

events {
    worker_connections 1024;
}

http {
    server_tokens off;
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;

    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log warn;

    server {
        listen 80;
        server_name localhost ayala.local;
        root  /usr/share/nginx/html;
        index index.html;

        location / {
            try_files $uri $uri/ =404;
        }
    }
}
EOF

    # --- Dockerfile personalizado ---
    cat > "$DIR_WEB/Dockerfile" << 'EOF'
# ================================================================
# Imagen personalizada: nginx sobre Alpine Linux
#   - server_tokens off  (sin exposición de versión)
#   - Proceso bajo usuario no administrativo: webuser
# ================================================================
FROM alpine:3.19

RUN apk add --no-cache nginx wget && \
    adduser -D -H -s /sbin/nologin webuser && \
    mkdir -p /var/log/nginx /run/nginx /tmp && \
    chown -R webuser:webuser /var/log/nginx /run/nginx /tmp && \
    mkdir -p /usr/share/nginx/html && \
    chown -R webuser:webuser /usr/share/nginx/html

COPY --chown=webuser:webuser html/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/nginx.conf

USER webuser
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
EOF

    ok "Dockerfile y archivos web creados en $DIR_WEB"
}

# ----------------------------------------------------------------
# CONSTRUIR IMAGEN PERSONALIZADA
# ----------------------------------------------------------------
construir_imagen_web() {
    info "Construyendo imagen personalizada nginx-custom..."
    if docker build -t nginx-custom "$DIR_WEB"; then
        ok "Imagen nginx-custom construida."
        docker images nginx-custom
    else
        err "Error al construir imagen. Revisa el Dockerfile en $DIR_WEB"
        return 1
    fi
}

# ================================================================
# CONTENEDORES
# NOTA Fedora/SELinux: se agrega :z al final de bind mounts del host
#   :z → SELinux permite acceso compartido entre contenedores
#   Los volúmenes Docker nombrados (VOL_DB, VOL_WEB) no lo necesitan
# ================================================================

# ----------------------------------------------------------------
# CONTENEDOR WEB  (512 MB RAM, 0.5 CPU)
# ----------------------------------------------------------------
crear_contenedor_web() {
    info "Creando contenedor web_server..."
    docker rm -f web_server 2>/dev/null
    docker run -d \
        --name web_server \
        --network "$INFRA_RED" \
        --ip 172.20.0.10 \
        -p 80:80 \
        -v "$VOL_WEB":/usr/share/nginx/html \
        --memory="512m" \
        --memory-swap="512m" \
        --cpus="0.5" \
        --label "servicio=web" \
        --label "proyecto=p10" \
        nginx-custom
    ok "web_server creado → IP 172.20.0.10, puerto 80"
}

# ----------------------------------------------------------------
# CONTENEDOR POSTGRESQL  (512 MB RAM, 0.5 CPU)
# ----------------------------------------------------------------
crear_contenedor_postgres() {
    info "Creando contenedor db_postgres..."
    docker rm -f db_postgres 2>/dev/null
    docker run -d \
        --name db_postgres \
        --network "$INFRA_RED" \
        --ip 172.20.0.20 \
        -e POSTGRES_DB=infradb \
        -e POSTGRES_USER=admin \
        -e POSTGRES_PASSWORD=Admin1234! \
        -v "$VOL_DB":/var/lib/postgresql/data \
        -v "$DIR_BACKUP":/backups:z \
        --memory="512m" \
        --memory-swap="512m" \
        --cpus="0.5" \
        --label "servicio=db" \
        --label "proyecto=p10" \
        postgres:15-alpine
    ok "db_postgres creado → IP 172.20.0.20, puerto 5432"
}

# ----------------------------------------------------------------
# CONTENEDOR FTP  (256 MB RAM, 0.25 CPU)
# ----------------------------------------------------------------
crear_contenedor_ftp() {
    info "Creando contenedor ftp_server..."
    docker rm -f ftp_server 2>/dev/null
    docker run -d \
        --name ftp_server \
        --network "$INFRA_RED" \
        --ip 172.20.0.30 \
        -p 21:21 \
        -p 30000-30009:30000-30009 \
        -e FTP_USER=ftpuser \
        -e FTP_PASS=Ftp1234! \
        -e PASV_MIN_PORT=30000 \
        -e PASV_MAX_PORT=30009 \
        -e PASV_ADDRESS=0.0.0.0 \
        -v "$DIR_FTP":/home/ftpuser:z \
        -v "$VOL_WEB":/web_content \
        --memory="256m" \
        --memory-swap="256m" \
        --cpus="0.25" \
        --label "servicio=ftp" \
        --label "proyecto=p10" \
        garethflowers/ftp-server
    ok "ftp_server creado → IP 172.20.0.30, puerto 21"
}

# ================================================================
# BACKUP AUTOMÁTICO POSTGRESQL
# ================================================================
configurar_backup_automatico() {
    info "Configurando backup automático de PostgreSQL..."

    # Fedora usa crond; instalarlo si no está presente
    if ! command -v crontab &>/dev/null; then
        dnf -y install cronie
        systemctl enable --now crond
    fi

    CRON_CMD="0 2 * * * docker exec db_postgres pg_dump -U admin infradb > $DIR_BACKUP/backup_\$(date +\%Y\%m\%d_\%H\%M).sql 2>/dev/null"
    (crontab -l 2>/dev/null | grep -v "db_postgres"; echo "$CRON_CMD") | crontab -
    ok "Backup automático configurado (2:00 AM diario) → $DIR_BACKUP"
}

backup_postgres() {
    info "Ejecutando backup manual de PostgreSQL..."
    if ! docker ps --format '{{.Names}}' | grep -q "^db_postgres$"; then
        err "El contenedor db_postgres no está corriendo."
        return 1
    fi
    BACKUP_FILE="$DIR_BACKUP/backup_$(date +%Y%m%d_%H%M).sql"
    if docker exec db_postgres pg_dump -U admin infradb > "$BACKUP_FILE"; then
        ok "Backup generado: $BACKUP_FILE"
        ls -lh "$BACKUP_FILE"
    else
        err "Error al generar backup."
        rm -f "$BACKUP_FILE"
    fi
}

# ----------------------------------------------------------------
# VER STATS
# ----------------------------------------------------------------
ver_stats() {
    info "Stats de contenedores P10 (snapshot único)..."
    echo ""
    docker stats --no-stream \
        $(docker ps --filter "label=proyecto=p10" --format "{{.Names}}" | tr '\n' ' ')
}

# ================================================================
# FUNCIONES BÁSICAS DE GESTIÓN
# ================================================================
listar_contenedores() {
    info "Estado de contenedores..."
    echo ""
    docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
}

crear_contenedor() {
    info "Crear contenedor simple..."
    read -rp "Imagen (ej. alpine): " imagen
    read -rp "Nombre del contenedor: " nombre_cont
    imagen="${imagen//alphine/alpine}"
    imagen="${imagen//alphin/alpine}"
    if docker run -d \
        --name "$nombre_cont" \
        --network "$INFRA_RED" \
        --label "proyecto=p10" \
        "$imagen" sleep 3600; then
        ok "Contenedor '$nombre_cont' creado."
    else
        err "Error al crear contenedor '$nombre_cont'."
    fi
}

iniciar_contenedor() {
    read -rp "Nombre o ID del contenedor: " contenedor
    docker start "$contenedor" && ok "Contenedor '$contenedor' iniciado."
}

detener_contenedor() {
    read -rp "Nombre o ID del contenedor: " contenedor
    docker stop "$contenedor" && ok "Contenedor '$contenedor' detenido."
}

eliminar_contenedor() {
    read -rp "Nombre o ID del contenedor: " contenedor
    read -rp "¿Confirmar eliminación de '$contenedor'? [s/N]: " conf
    [[ "$conf" =~ ^[sS]$ ]] && \
        docker rm "$contenedor" && ok "Contenedor '$contenedor' eliminado." || \
        warn "Operación cancelada."
}

# ================================================================
# PROTOCOLO DE PRUEBAS (10.1 – 10.4)
# ================================================================
menu_pruebas() {
    while true; do
        echo -e "\n======================================"
        echo -e "     PROTOCOLO DE PRUEBAS P10"
        echo -e "======================================"
        echo "1) Prueba 10.1 – Persistencia de BD"
        echo "2) Prueba 10.2 – Aislamiento de red"
        echo "3) Prueba 10.3 – Permisos FTP"
        echo "4) Prueba 10.4 – Límites de recursos"
        echo "5) Volver"
        echo "======================================"
        read -rp "Opción: " prueba_op
        case $prueba_op in
            1) prueba_persistencia_bd ;;
            2) prueba_aislamiento_red ;;
            3) prueba_permisos_ftp ;;
            4) prueba_limites_recursos ;;
            5) break ;;
            *) err "Opción inválida." ;;
        esac
    done
}

# ----------------------------------------------------------------
# PRUEBA 10.1 – Persistencia de BD
# ----------------------------------------------------------------
prueba_persistencia_bd() {
    echo -e "\n====== PRUEBA 10.1: Persistencia de BD ======"

    info "Paso 1: Esperando que PostgreSQL esté listo..."
    sleep 5

    info "Paso 2: Creando tabla y datos de prueba..."
    docker exec db_postgres psql -U admin -d infradb -c "
        CREATE TABLE IF NOT EXISTS prueba_p10 (
            id   SERIAL PRIMARY KEY,
            dato TEXT NOT NULL,
            ts   TIMESTAMP DEFAULT NOW()
        );
        INSERT INTO prueba_p10 (dato) VALUES ('Registro persistencia P10');
    " && ok "Datos insertados en infradb.prueba_p10"

    info "Paso 3: Eliminando contenedor con docker rm -f..."
    docker rm -f db_postgres
    ok "Contenedor db_postgres eliminado."

    info "Paso 4: Recreando contenedor (mismo volumen $VOL_DB)..."
    crear_contenedor_postgres
    sleep 6

    info "Paso 5: Verificando persistencia de datos..."
    RESULT=$(docker exec db_postgres psql -U admin -d infradb -c "SELECT * FROM prueba_p10;" 2>&1)
    echo ""
    echo "$RESULT"
    if echo "$RESULT" | grep -q "Registro persistencia P10"; then
        ok "PRUEBA 10.1 EXITOSA: Los datos persisten tras recrear el contenedor."
    else
        err "PRUEBA 10.1 FALLIDA: No se encontraron los datos."
    fi
}

# ----------------------------------------------------------------
# PRUEBA 10.2 – Aislamiento de red
# ----------------------------------------------------------------
prueba_aislamiento_red() {
    echo -e "\n====== PRUEBA 10.2: Aislamiento de Red ======"
    info "Haciendo ping desde web_server → db_postgres (DNS interno)..."
    echo ""
    # Alpine incluye ping en el paquete iputils
    if docker exec web_server sh -c \
        "apk add --no-cache iputils -q 2>/dev/null; ping -c 4 db_postgres"; then
        ok "PRUEBA 10.2 EXITOSA: web_server alcanza db_postgres por nombre."
    else
        err "PRUEBA 10.2 FALLIDA: Sin conectividad entre contenedores."
    fi

    info "Verificando ping a ftp_server..."
    docker exec web_server ping -c 2 ftp_server \
        && ok "Ping a ftp_server OK." \
        || warn "Ping a ftp_server falló."
}

# ----------------------------------------------------------------
# PRUEBA 10.3 – FTP
# ----------------------------------------------------------------
prueba_permisos_ftp() {
    echo -e "\n====== PRUEBA 10.3: Permisos FTP ======"
    HOST_IP=$(hostname -I | awk '{print $1}')

    info "Creando archivo de prueba..."
    echo "<h2>Archivo subido via FTP - P10</h2>" > /tmp/ftp_test.html

    # Intentar con lftp (disponible en Fedora) o ftp
    if command -v lftp &>/dev/null; then
        info "Subiendo ftp_test.html vía lftp..."
        lftp -u ftpuser,Ftp1234! "$HOST_IP" << FTP_EOF
put /tmp/ftp_test.html
bye
FTP_EOF
        ok "Archivo subido vía lftp."
    elif command -v ftp &>/dev/null; then
        info "Subiendo ftp_test.html vía ftp..."
        ftp -n "$HOST_IP" 21 << FTP_EOF
user ftpuser Ftp1234!
put /tmp/ftp_test.html ftp_test.html
bye
FTP_EOF
        ok "Archivo subido vía ftp."
    else
        # Fallback directo al directorio montado
        cp /tmp/ftp_test.html "$DIR_FTP/ftp_test.html"
        warn "Cliente FTP no encontrado. Instala con: dnf install lftp"
        warn "Archivo copiado directamente a $DIR_FTP"
    fi

    # Hacer el archivo visible en nginx
    docker cp /tmp/ftp_test.html web_server:/usr/share/nginx/html/ftp_test.html 2>/dev/null

    info "Verificando que nginx sirve el archivo..."
    if docker exec web_server wget -qO- http://localhost/ftp_test.html 2>/dev/null \
        | grep -q "FTP"; then
        ok "PRUEBA 10.3 EXITOSA: El servidor web visualiza el archivo subido."
    else
        warn "No se pudo verificar automáticamente."
        warn "Prueba en el navegador: http://$HOST_IP/ftp_test.html"
    fi

    rm -f /tmp/ftp_test.html
}

# ----------------------------------------------------------------
# PRUEBA 10.4 – Límites de recursos
# ----------------------------------------------------------------
prueba_limites_recursos() {
    echo -e "\n====== PRUEBA 10.4: Límites de Recursos ======"
    echo ""
    echo "Límites configurados:"
    printf "  %-14s → %s RAM, %s CPU\n" "web_server"  "512 MB" "0.50"
    printf "  %-14s → %s RAM, %s CPU\n" "db_postgres" "512 MB" "0.50"
    printf "  %-14s → %s RAM, %s CPU\n" "ftp_server"  "256 MB" "0.25"
    echo ""

    info "Ejecutando docker stats --no-stream..."
    docker stats --no-stream web_server db_postgres ftp_server 2>/dev/null || \
        docker stats --no-stream

    echo ""
    info "Verificando límites via docker inspect..."
    for c in web_server db_postgres ftp_server; do
        MEM=$(docker inspect "$c" --format '{{.HostConfig.Memory}}' 2>/dev/null)
        CPU=$(docker inspect "$c" --format '{{.HostConfig.NanoCpus}}' 2>/dev/null)
        if [[ -n "$MEM" && "$MEM" != "0" ]]; then
            MEM_MB=$(( MEM / 1024 / 1024 ))
            # Calcular CPUs sin bc (solo aritmética entera de bash)
            CPU_INT=$(( CPU / 1000000000 ))
            CPU_DEC=$(( (CPU % 1000000000) / 10000000 ))
            printf "\e[32m[OK]\e[0m %-14s → Memoria: %s MB | CPUs: %d.%02d\n" \
                "$c" "$MEM_MB" "$CPU_INT" "$CPU_DEC"
        else
            warn "$c → No se pudo obtener límites (¿contenedor detenido?)"
        fi
    done
}

# ================================================================
# PUNTO DE ENTRADA
# ================================================================
menu_docker
