#!/bin/bash
# ============================================================
# menu_principal.sh — Punto de entrada único
# Uso: sudo bash menu_principal.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verificar dependencias antes de cargar
for archivo in functions.sh menus.sh; do
    if [[ ! -f "$SCRIPT_DIR/$archivo" ]]; then
        echo "[ERROR] No se encontró: $archivo"
        echo "        Coloca functions.sh, menus.sh y menu_principal.sh en el mismo directorio."
        exit 1
    fi
done

source "$SCRIPT_DIR/menus.sh"   # menus.sh ya hace source de functions.sh

verificar_root

while true; do
    clear
    
    echo ""
    echo "  1) Práctica 1 — Diagnóstico del Sistema"
    echo "  2) Práctica 2 — DHCP + DNS (BIND9)"
    echo "  3) Práctica 3 — SSH Manager"
    echo ""
    echo "  0) Salir"
    echo ""
    read -rp "Selecciona una práctica: " opcion

    case $opcion in
        1) menu_p1_diagnostico ;;
        2) menu_p2_dhcp_dns ;;
        3) menu_p3_ssh ;;
        0)
            echo ""
            log_info "Saliendo. ¡Hasta luego!"
            exit 0
            ;;
        *)
            log_warn "Opción no válida."
            sleep 1
            ;;
    esac
done
