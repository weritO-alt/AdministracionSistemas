#!/bin/bash
echo "Nombre del equipo $(hostname)"
echo "IP actual:"
hostname -I
echo "Espacio de disco:"
df -h /
