#!/bin/bash
# ============================================================
# menus.sh — Todos los menús de prácticas
# No ejecutar directamente, es llamado por menu_principal.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

# ────────────────────────────────────────────────────────────
# PRÁCTICA 1 — DIAGNÓSTICO DEL SISTEMA
# ────────────────────────────────────────────────────────────

menu_p1_diagnostico() {
    while true; do
        clear
       
        echo ""
        echo "  1) Mostrar información del sistema"
        echo "  2) Volver al Menú Principal"
        echo ""
        read -rp "Selecciona una opción: " opcion
        case $opcion in
            1) p1_mostrar_info ;;
            2) return ;;
            *) log_warn "Opción inválida." ; sleep 1 ;;
        esac
    done
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 2 — DHCP + DNS
# ────────────────────────────────────────────────────────────

_submenu_dhcp() {
    while true; do
        clear
        
        echo ""
        echo "  1) Instalar DHCP"
        echo "  2) Configurar Scope"
        echo "  3) Ver Clientes (Leases)"
        echo "  4) Desinstalar DHCP"
        echo "  5) Volver"
        echo ""
        read -rp "Opción: " op
        case "$op" in
            1) instalar_dhcp ;;
            2) configurar_scope ;;
            3) ver_clientes_dhcp ;;
            4)
                read -rp "¿Seguro que quieres desinstalar DHCP? (s/n): " confirm
                if [[ "$confirm" == "s" ]]; then
                    dnf remove -y dhcp-server
                    log_exito "DHCP desinstalado."
                    read -p "Enter para continuar..."
                fi
                ;;
            5) return ;;
            *) log_warn "Opción no válida." ; sleep 1 ;;
        esac
    done
}

_submenu_dns() {
    while true; do
        clear
        
        echo ""
        echo "  1) Instalar DNS"
        echo "  2) Agregar Dominio"
        echo "  3) Listar Dominios"
        echo "  4) Eliminar Dominio"
        echo "  5) Reparar DNS  ← usar si named no levanta"
        echo "  6) Desinstalar DNS"
        echo "  7) Volver"
        echo ""
        read -rp "Opción: " op
        case "$op" in
            1) instalar_dns ;;
            2) agregar_dominio_dns ;;
            3) listar_dominios_dns ;;
            4) eliminar_dominio_dns ;;
            5) reparar_custom_zones ;;
            6)
                read -rp "¿Seguro que quieres desinstalar DNS? (s/n): " confirm
                if [[ "$confirm" == "s" ]]; then
                    dnf remove -y bind bind-utils
                    log_exito "DNS desinstalado."
                    read -p "Enter para continuar..."
                fi
                ;;
            7) return ;;
            *) log_warn "Opción no válida." ; sleep 1 ;;
        esac
    done
}

menu_p2_dhcp_dns() {
    while true; do
        clear
      
        echo ""
        echo "  1) DHCP"
        echo "  2) DNS"
        echo "  3) Estado de Servicios"
        echo "  4) Volver al Menú Principal"
        echo ""
        read -rp "Opción: " op
        case "$op" in
            1) _submenu_dhcp ;;
            2) _submenu_dns ;;
            3) verificar_estado_servicios ;;
            4) return ;;
            *) log_warn "Opción no válida." ; sleep 1 ;;
        esac
    done
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 3 — SSH MANAGER
# ────────────────────────────────────────────────────────────

menu_p3_ssh() {
    while true; do
        clear
     
        echo ""
        echo "  1) Verificar instalación SSH local"
        echo "  2) Instalar y configurar SSH local"
        echo "  3) Conectarse a una VM en red interna"
        echo "  4) Volver al Menú Principal"
        echo ""
        read -rp "Selecciona una opción: " opcion
        case $opcion in
            1) ssh_verificar_instalacion ; read -p "Enter para continuar..." ;;
            2) ssh_instalar_configurar   ; read -p "Enter para continuar..." ;;
            3) ssh_conectarse ;;
            4) return ;;
            *) log_warn "Opción inválida." ; sleep 1 ;;
        esac
    done
}
