# ============================================================
# menu_principal.ps1 - Punto de entrada unico
# Uso: PowerShell -ExecutionPolicy Bypass -File menu_principal.ps1
# ============================================================

foreach ($archivo in @("functions.ps1", "menus.ps1")) {
    if (-not (Test-Path "$PSScriptRoot\$archivo")) {
        Write-Host "[ERROR] No se encontro: $archivo" -ForegroundColor Red
        Write-Host "        Coloca functions.ps1, menus.ps1 y menu_principal.ps1 en el mismo directorio." -ForegroundColor Red
        exit 1
    }
}

. "$PSScriptRoot\menus.ps1"

Verificar-Admin

while ($true) {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   WINDOWS SERVER - MENU PRINCIPAL         " -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ("  Equipo : {0}" -f $env:COMPUTERNAME) -ForegroundColor White
    $ipLocal = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -First 1 -ExpandProperty IPAddress)
    Write-Host ("  IP     : {0}" -f $ipLocal) -ForegroundColor White
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1) Practica 1 - Diagnostico del Sistema"
    Write-Host "  2) Practica 2 - DHCP + DNS"
    Write-Host "  3) Practica 3 - SSH Manager"
    Write-Host ""
    Write-Host "  0) Salir"
    Write-Host ""
    $opcion = Read-Host "Selecciona una practica"

    switch ($opcion) {
        "1" { Menu-P1-Diagnostico }
        "2" { Menu-P2-DHCP-DNS }
        "3" { Menu-P3-SSH }
        "0" { Write-Host "Saliendo..."; exit 0 }
        Default { Write-Host "[WARN] Opcion no valida." -ForegroundColor Yellow ; Start-Sleep -Seconds 1 }
    }
}
