#!/bin/bash
if [ "$(whoami)" == "root" ]; then echo "root ok"; else echo "run as root!"; exit 1; fi;
#IPTABLES_PATH=$(whereis iptables | awk '{print $2}')
#IPSET_PATH=$(whereis ipset | awk '{print $2}')
#SORT_PATH=$(whereis sort | awk '{print $2}')
#GREP_PATH=$(whereis grep | awk '{print $2}')
BLOCKLISTDE="https://lists.blocklist.de/lists/all.txt"
CRWALERS="https://isc.sans.edu/api/threatcategory/research?json"


#if [ -f $IPTABLES_PATH ]; then echo "iptables OK"; else echo "Cannot find [ iptables ]. Is it installed? Exiting"; exit 1; fi;
if ! command -v iptables >/dev/null; then  echo "I require iptables but it's not installed."; apt install -y iptables; else echo "iptables OK"; fi;
#if [ -f $IPSET_PATH ]; then echo "ipset OK"; else echo "Cannot find [ ipset ]. Is it installed? Exiting"; exit 1; fi;
if ! command -v ipset >/dev/null; then  echo "I require ipset but it's not installed."; apt install -y ipset; else echo "iptables OK"; fi;
#if [ -f $SORT_PATH ]; then echo "sort OK"; else echo "Cannot find [ sort ]. Is it installed? Exiting"; exit 1; fi;
if ! command -v sort >/dev/null; then  echo "I require sort but it's not installed."; else echo "sort OK"; fi;
#if [ -x $JQ_PATH ]; then echo "jq OK"; else echo "jq not installed, installing"; apt install -y jq; fi;
if ! command -v jq >/dev/null; then  echo "I require jq but it's not installed."; apt install -y jq; fi;  
#if [ ! -f $GREP_PATH ]; then echo "Cannot find [ grep ]. Is it installed? Exiting"; exit 1; fi;
if ! command -v grep >/dev/null; then  echo "I require grep but it's not installed."; apt install -y grep; else echo "grep OK"; fi;

echo "Downloading the most recent IP list from $BLOCKLISTDE ... and adding them to ipset blocklistde"
ipset create blocklistde hash:ip
curl -s https://lists.blocklist.de/lists/all.txt | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | xargs -L1 ipset add blocklistde 2>&1
echo "Downloading the most recent IP list from $CRWALERS ... and adding them to ipset crawlers"
ipset create crawler_bots hash:ip
curl -s https://isc.sans.edu/api/threatcategory/research?json | jq '.[] | {ipv4}' | grep ':' | awk '{ print $2 }' | tr -d '"' | xargs -L1 ipset add crawler_bots 2>&1
echo "Adding the iptables rules..."
iptables -I INPUT -m set --match-set crawler_bots src -j DROP
iptables -I INPUT -m set --match-set blocklistde src -j DROP
