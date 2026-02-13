#!/bin/bash

validar_ip() {
    local ip=$1
    if [[ $ip == "0.0.0.0" || $ip == "255.255.255.255" || $ip == "127.0.0.1" ]]; then
        return 1
    fi
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octetos <<< "$ip"
        for octeto in "${octetos[@]}"; do
            if [[ $octeto -lt 0 || $octeto -gt 255 ]]; then return 1; fi
        done
        return 0
    fi
    return 1
}

ip_a_numero() {
    local a b c d
    IFS='.' read -r a b c d <<< "$1"
    echo "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
}

while true; do
    clear
    echo "1) Verificar estado"
    echo "2) Instalar/Desinstalar"
    echo "3) Configurar Ambito"
    echo "4) Ver Leases"
    echo "5) Limpiar/Eliminar Leases"
    echo "6) Salir"

    read -p "Seleccione una opcion: " opcion
    
    case $opcion in
        "1")
            if systemctl is-active --quiet dhcpd; then
                echo -e "\e[32m\nEstado del servicio: ACTIVO\e[0m"
            else
                echo -e "\e[31m\nEstado del servicio: INACTIVO o ERROR\e[0m"
                sudo journalctl -u dhcpd -n 5 --no-pager
            fi
            read -p "Presione Enter..."
            ;;
        "2")
            echo "Escriba 'I' para Instalar o 'D' para Desinstalar"
            read accion
            if [[ ${accion^^} == 'I' ]]; then
                sudo dnf install -y dhcp-server
            elif [[ ${accion^^} == 'D' ]]; then
                sudo dnf remove -y dhcp-server
            fi
            read -p "Presione Enter..."
            ;;
       "3")
            if ! rpm -q dhcp-server &> /dev/null; then
                echo -e "\e[31mError: Instale el rol primero.\e[0m"
                read -p "Presione Enter..."
                continue
            fi
        
            read -p "Nombre del nuevo Ambito: " nombreAmbito
            read -p "IP Inicial: " ipInicio
            validar_ip "$ipInicio" || { echo "IP no valida"; sleep 2; continue; }
            
            read -p "IP Final: " ipFinal
            validar_ip "$ipFinal" || { echo "IP no valida"; sleep 2; continue; }
        
            inicio_int=$(ip_a_numero "$ipInicio")
            final_int=$(ip_a_numero "$ipFinal")
        
            if [ "$inicio_int" -ge "$final_int" ]; then
                echo -e "\e[31mError: La IP final debe ser mayor a la inicial.\e[0m"
                read -p "Presione Enter..."
                continue
            fi

            read -p "Mascara de red: " mascara
        
            while true; do
                read -p "Lease Time en segundos: " ltime
                [[ -z "$ltime" ]] && ltime="3600" && break
                if [[ "$ltime" =~ ^[0-9]+$ ]] && [ "$ltime" -gt 0 ]; then
                    break
                else
                    echo -e "\e[31mError: Ingrese un numero entero mayor a 0.\e[0m"
                fi
            done
        
            read -p "Gateway: " gw
            read -p "DNS: " dns
            [[ -z "$gw" ]] && gw="$ipInicio"
            [[ -z "$dns" ]] && dns="8.8.8.8"
        
            prefix=$(ipcalc -p "$ipInicio" "$mascara" | cut -d= -f2)
            net_id=$(ipcalc -n "$ipInicio" "$mascara" | cut -d= -f2)
        
            echo -e "\e[33mReconfigurando interfaz enp0s8 para cualquier clase...\e[0m"
            
            sudo nmcli connection delete enp0s8 &> /dev/null
            
            sudo nmcli connection add type ethernet ifname enp0s8 con-name enp0s8 ipv4.method manual ipv4.addresses "$ipInicio/$prefix" ipv4.gateway "$gw" ipv4.dns "$dns"
            
            sudo ip addr flush dev enp0s8
            
            sudo nmcli connection up enp0s8 &> /dev/null
            
            sleep 2
        
            sudo bash -c "cat > /etc/dhcp/dhcpd.conf <<EOF
authoritative;
ddns-update-style none;

subnet $net_id netmask $mascara {
    range $ipInicio $ipFinal;
    option routers $gw;
    option domain-name-servers $dns;
    default-lease-time $ltime;
    max-lease-time $((ltime * 2));
}
EOF"
        
            # Ajustamos el servicio para que escuche en la interfaz recien creada
            sudo mkdir -p /etc/systemd/system/dhcpd.service.d
            sudo bash -c "cat > /etc/systemd/system/dhcpd.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/dhcpd -f -cf /etc/dhcp/dhcpd.conf -user dhcpd -group dhcpd --no-pid enp0s8
EOF"
            
            sudo systemctl daemon-reload
            sudo systemctl stop dhcpd &> /dev/null
            sudo sh -c "> /var/lib/dhcpd/dhcpd.leases"
            
            if sudo systemctl start dhcpd; then
                echo -e "\e[32m¡Servidor DHCP Activo en enp0s8!\e[0m"
                echo -e "\e[32mConfiguracion aplicada: $ipInicio con mascara $mascara\e[0m"
                ip addr show enp0s8 | grep "inet "
            else
                echo -e "\e[31mError al iniciar. Revisa journalctl -u dhcpd\e[0m"
            fi
            read -p "Presione Enter..."
            ;;
        "4")
            echo -e "\e[33m\nLeases activos:\e[0m"
            [ -f /var/lib/dhcpd/dhcpd.leases ] && sudo grep -E "lease|hostname|ends" /var/lib/dhcpd/dhcpd.leases || echo "Sin leases."
            read -p "Presione Enter..."
            ;;
        "5")
            sudo systemctl stop dhcpd
            sudo sh -c "> /var/lib/dhcpd/dhcpd.leases"
            sudo systemctl start dhcpd
            echo -e "\e[32mLeases limpiados.\e[0m"
            read -p "Presione Enter..."
            ;;
        "6") exit 0 ;;
    esac
done
