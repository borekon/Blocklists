#!/bin/bash
if [ "$(whoami)" == "root" ]; then echo "root ok"; else echo "run as root!"; exit 1; fi;
#apt update && apt install -y iptables jq ipset coreutils grep
IPTABLES_PATH=$(whereis iptables | awk '{print $2}')
IPSET_PATH=$(whereis ipset | awk '{print $2}')
SORT_PATH=$(whereis sort | awk '{print $2}')
GREP_PATH=$(whereis grep | awk '{print $2}')
JQ_PATH=$(whereis jq | awk '{print $2}')
BLOCKLISTDE="https://lists.blocklist.de/lists/all.txt"
CRWALERS="https://isc.sans.edu/api/threatcategory/research?json"
ABUSE="https://api.abuseipdb.com/api/v2/blacklist"
abuse_key="INSERT_YOUR_API_KEY_HERE" #https://www.abuseipdb.com/account/api

installed() {
    # $1 should be the command to look for
    if ! [ -x "$(command -v $1)" ]; then
        echo "$1 is not available. Please install it and run again."
        exit 1
    fi
}

installed iptables
installed ipset
installed sort
installed jq
installed grep

echo "Downloading the most recent IP list from $BLOCKLISTDE ... and adding them to ipset blocklistde"
$(whereis ipset | cut -d" " -f 2) create blocklistde hash:ip
curl -s https://lists.blocklist.de/lists/all.txt | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | xargs -L1 $IPSET_PATH add blocklistde 2>&1
echo "Downloading the most recent IP list from $CRWALERS ... and adding them to ipset crawler_bots"
$(whereis ipset | cut -d" " -f 2) create crawler_bots hash:ip
curl -s https://isc.sans.edu/api/threatcategory/research?json | jq '.[] | {ipv4}' | grep ':' | awk '{ print $2 }' | tr -d '"' | xargs -L1 $IPSET_PATH add crawler_bots 2>&1
echo "Downloading the most recent IP list from $ABUSE and adding them to abuseipdb"
$(whereis ipset | cut -d" " -f 2) create abuseipdb hash:ip
curl -G -H "key: $abuse_key" -H "Accept: text/plain" -d confidenceMinimum=90 https://api.abuseipdb.com/api/v2/blacklist | grep -v : | xargs -L1 $IPSET_PATH add abuseipdb 2>&1
echo "Adding the iptables rules..."
$IPTABLES_PATH -I INPUT -m set --match-set crawler_bots src -j DROP
$IPTABLES_PATH -I INPUT -m set --match-set blocklistde src -j DROP
$IPTABLES_PATH -I INPUT -m set --match-set abuseipdb src -j DROP
