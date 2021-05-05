#!/bin/bash

IPTABLES_PATH="/sbin/iptables"
IPSET_PATH="/sbin/ipset"
SORT_PATH="/usr/bin/sort"
GREP_PATH="/bin/grep"
BLOCKLISTDE="https://lists.blocklist.de/lists/all.txt"
CRWALERS="https://isc.sans.edu/api/threatcategory/research?json"


if [ -f $IPTABLES_PATH ]; then echo "iptables OK"; else echo "Cannot find [ iptables ]. Is it installed? Exiting"; exit 1; fi;
#hash iptables 2>/dev/null || { echo >&2 "I require iptables but it's not installed.  Aborting."; exit 1; }
#more in https://stackoverflow.com/questions/592620/how-can-i-check-if-a-program-exists-from-a-bash-script
if [ -f $IPSET_PATH ]; then echo "ipset OK"; else echo "Cannot find [ ipset ]. Is it installed? Exiting"; exit 1; fi;
if [ -f $SORT_PATH ]; then echo "sort OK"; else echo "Cannot find [ sort ]. Is it installed? Exiting"; exit 1; fi;
if [ ! -f $GREP_PATH ]; then echo "Cannot find [ grep ]. Is it installed? Exiting"; exit 1; fi;

echo "Downloading the most recent IP list from $BLOCKLISTDE ... and adding them to ipset blocklistde"
curl -s https://lists.blocklist.de/lists/all.txt | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | xargs -L1 ipset add blocklistde
echo "Downloading the most recent IP list from $BLOCKLISTDE ... and adding them to ipset crawlers"
curl -s https://isc.sans.edu/api/threatcategory/research?json | jq '.[] | {ipv4}' | grep ':' | awk '{ print $2 }' | tr -d '"' | xargs -L1 ipset add crawler_bots
echo "Adding the iptables rules..."
iptables -I INPUT -m set --match-set crawler_bots src -j DROP
iptables -I INPUT -m set --match-set blocklistde src -j DROP