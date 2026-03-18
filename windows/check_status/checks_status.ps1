Write-Host ¨Nombre del equipo: ¨ $env:COMPUTERNAME

$ip = Get-NetIPAddress -AddressFamily IPv4 |
Select-Object -First 1 -ExpandProperty IPAddress

Write-Host "IP actual: " $ip

$disk = Get-PSDrive C

$totalGb = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2)
$freeGB = [math]::Round($disk.Free / 1GB, 2)

Write-Host "Espacio en disco: "
Write-Host "Total: " $totalGB "GB"
Write-Host "Libre: " $freeGB  "GB"





