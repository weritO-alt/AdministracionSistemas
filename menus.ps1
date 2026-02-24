# ============================================================
# menus.ps1 — Todos los menús de prácticas
# No ejecutar directamente, es llamado por menu_principal.ps1
# ============================================================

. "$PSScriptRoot\functions.ps1"

# ────────────────────────────────────────────────────────────
# PRÁCTICA 1 — DIAGNÓSTICO DEL SISTEMA
# ────────────────────────────────────────────────────────────

function Menu-P1-Diagnostico {
    while ($true) {
        Clear-Host
        
        Write-Host ""
        Write-Host "  1) Mostrar informacion del sistema"
        Write-Host "  2) Volver al Menu Principal"
        Write-Host ""
        $op = Read-Host "Selecciona una opcion"
        switch ($op) {
            "1" { P1-Mostrar-Info }
            "2" { return }
            Default { Log-Warn "Opcion no valida." ; Start-Sleep -Seconds 1 }
        }
    }
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 2 — DHCP + DNS
# ────────────────────────────────────────────────────────────

function _Submenu-DHCP {
    while ($true) {
        Clear-Host
      
        Write-Host ""
        Write-Host "  1) Instalar DHCP"
        Write-Host "  2) Configurar Scope"
        Write-Host "  3) Ver Clientes (Leases)"
        Write-Host "  4) Desinstalar DHCP"
        Write-Host "  5) Volver"
        Write-Host ""
        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { Instalar-Rol-DHCP }
            "2" { Configurar-Todo-Scope }
            "3" { Monitorear-Clientes }
            "4" {
                $confirm = Read-Host "Seguro que quieres desinstalar DHCP? (s/n)"
                if ($confirm -eq "s") {
                    Uninstall-WindowsFeature DHCP
                    Log-Exito "DHCP desinstalado."
                    Read-Host "Enter para continuar..."
                }
            }
            "5" { return }
            Default { Log-Warn "Opcion no valida." ; Start-Sleep -Seconds 1 }
        }
    }
}

function _Submenu-DNS {
    while ($true) {
        Clear-Host
      
        Write-Host ""
        Write-Host "  1) Instalar DNS"
        Write-Host "  2) Agregar Dominio"
        Write-Host "  3) Listar Dominios"
        Write-Host "  4) Eliminar Dominio"
        Write-Host "  5) Desinstalar DNS"
        Write-Host "  6) Volver"
        Write-Host ""
        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { Instalar-DNS }
            "2" { Agregar-Dominio-DNS }
            "3" { Listar-Dominios-DNS }
            "4" { Eliminar-Dominio-DNS }
            "5" {
                $confirm = Read-Host "Seguro que quieres desinstalar DNS? (s/n)"
                if ($confirm -eq "s") {
                    Uninstall-WindowsFeature DNS -Remove
                    Log-Exito "DNS desinstalado."
                    Read-Host "Enter para continuar..."
                }
            }
            "6" { return }
            Default { Log-Warn "Opcion no valida." ; Start-Sleep -Seconds 1 }
        }
    }
}

function Menu-P2-DHCP-DNS {
    while ($true) {
        Clear-Host
        
        Write-Host ""
        Write-Host "  1) DHCP"
        Write-Host "  2) DNS"
        Write-Host "  3) Estado de Servicios"
        Write-Host "  4) Volver al Menu Principal"
        Write-Host ""
        $op = Read-Host "Opcion"
        switch ($op) {
            "1" { _Submenu-DHCP }
            "2" { _Submenu-DNS }
            "3" { Verificar-Estado-Servicios }
            "4" { return }
            Default { Log-Warn "Opcion no valida." ; Start-Sleep -Seconds 1 }
        }
    }
}

# ────────────────────────────────────────────────────────────
# PRÁCTICA 3 — SSH MANAGER
# ────────────────────────────────────────────────────────────

function Menu-P3-SSH {
    while ($true) {
        Clear-Host
       
        Write-Host ""
        Write-Host "  1) Verificar instalacion SSH local"
        Write-Host "  2) Instalar y configurar SSH local"
        Write-Host "  3) Conectarse a un servidor remoto"
        Write-Host "  4) Volver al Menu Principal"
        Write-Host ""
        $op = Read-Host "Selecciona una opcion"
        switch ($op) {
            "1" { SSH-Verificar-Instalacion ; Read-Host "Enter para continuar..." }
            "2" { SSH-Instalar-Configurar   ; Read-Host "Enter para continuar..." }
            "3" { SSH-Conectarse }
            "4" { return }
            Default { Log-Warn "Opcion invalida." ; Start-Sleep -Seconds 1 }
        }
    }
}
