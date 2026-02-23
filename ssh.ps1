function Instalar-Servidor {
    Write-Host "--- INSTALANDO SSH EN WINDOWS ---" -ForegroundColor Cyan
    
    $capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($capability.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name $capability.Name
    }

    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service -Name sshd

    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
    }

    Write-Host "[OK] SSH listo. Servicio en automático y Firewall abierto." -ForegroundColor Green
}

function Conectar-Remoto {
    $ip = Read-Host "IP del servidor remoto"
    $user = Read-Host "Usuario"
    ssh "$user@$ip"
}

while ($true) {
    Write-Host "`n--- SSH MANAGER---"
    Write-Host "1) Instalar y Activar Servidor SSH"
    Write-Host "2) Conectarse a otro servidor"
    Write-Host "3) Salir"
    $op = Read-Host "Selecciona una opción"

    switch ($op) {
        "1" { Instalar-Servidor }
        "2" { Conectar-Remoto }
        "3" { exit }
        Default { Write-Host "Opción no válida" }
    }
}
