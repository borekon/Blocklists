#!/bin/bash
# Actualiza una lista de bloqueo ipset desde múltiples fuentes

SET_NAME="blacklist"
TMP_SET="${SET_NAME}_tmp"

# Listas de bloqueo (puedes añadir más URLs aquí)
LISTS=(
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    "https://www.spamhaus.org/drop/drop.txt"
    "https://www.spamhaus.org/drop/edrop.txt"
    "https://lists.blocklist.de/lists/all.txt"
)

# Crear set principal si no existe
if ! ipset list -n | grep -q "^$SET_NAME\$"; then
    ipset create $SET_NAME hash:ip family inet hashsize 4096 maxelem 65536
fi

# Crear set temporal
ipset create $TMP_SET hash:ip family inet hashsize 4096 maxelem 65536

# Descargar y cargar IPs
for url in "${LISTS[@]}"; do
    echo "Descargando: $url"
    curl -s "$url" | grep -Eo '^[0-9.]+(/[0-9]+)?' | while read ip; do
        ipset add $TMP_SET $ip 2>/dev/null
    done
done

# Reemplazar el set viejo por el nuevo
ipset swap $SET_NAME $TMP_SET
ipset destroy $TMP_SET

# Bloqueo antes de DNAT → tabla raw PREROUTING
if ! iptables -t raw -C PREROUTING -m set --match-set $SET_NAME src -j DROP 2>/dev/null; then
    iptables -t raw -I PREROUTING 1 -m set --match-set $SET_NAME src -j DROP
    echo "Regla añadida en tabla raw PREROUTING para bloquear antes de DNAT"
else
    echo "La regla en tabla raw PREROUTING ya existe."
fi

# Añadir regla de iptables si no existe
if ! iptables -C INPUT -m set --match-set $SET_NAME src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set $SET_NAME src -j DROP
    echo "Regla añadida a iptables: DROP tráfico desde $SET_NAME"
else
    echo "La regla de iptables ya existe."
fi


echo "Actualización completada: $(ipset list $SET_NAME | grep -c '^[0-9]') IPs bloqueadas."
