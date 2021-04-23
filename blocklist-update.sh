#!/bin/bash

# The download path to the file which contains all the IP addresses
TO_DOWNLOAD="https://lists.blocklist.de/lists/all.txt"

# Other settings; Edit if necesarry
CHAINNAME="blocklist-de"
ACTION="DROP" # Can be DROP or REJECT
IPTABLES_PATH="/sbin/iptables"
IPSET_PATH="/sbin/ipset"
SORT_PATH="/usr/bin/sort"
MAIL_PATH="/usr/bin/mail"
GREP_PATH="/bin/grep"
MAIL=1

if [ -f $IPTABLES_PATH ]; then echo "iptables OK"; else echo "Cannot find [ iptables ]. Is it installed? Exiting"; exit 1; fi;
#hash iptables 2>/dev/null || { echo >&2 "I require iptables but it's not installed.  Aborting."; exit 1; }
#more in https://stackoverflow.com/questions/592620/how-can-i-check-if-a-program-exists-from-a-bash-script
if [ -f $IPSET_PATH ]; then echo "ipset OK"; else echo "Cannot find [ ipset ]. Is it installed? Exiting"; exit 1; fi;
if [ -f $SORT_PATH ]; then echo "sort OK"; else echo "Cannot find [ sort ]. Is it installed? Exiting"; exit 1; fi;
if [ -f $MAIL_PATH ]; then echo "mail OK"; else echo "Cannot find [ mail ]. Is it installed? No mail report will be sent"; MAIL=0; fi;
if [ ! -f $GREP_PATH ]; then echo "Cannot find [ grep ]. Is it installed? Exiting"; exit 1; fi;

# E-Mail variables
MAILLOG="/var/log/blocklist-update.log"
MAIL_SENDER=$(whoami) #this defines a system-user without a shell or password. It's used as the e-mail sender name. You can create one like this: useradd -M -N -s /usr/sbin/nologin myuser && passwd -d myuser
MAIL_SUBJECT="ERROR - IP blocklist script failed to download the IP set"
if [ $MAIL" == 1 ]; then read -t 15 -p "Insert a mail to send the log. Separate with space to send to multiple recipients: " MAIL_RECIPIENTS; fi;
if [ ! "$MAIL_RECIPIENTS" ]; then MAIL_RECIPIENTS="$(whoami)@$HOSTNAME"; else echo "Address: " $MAIL_RECIPIENTS; fi;

BLOCKLIST_FILE="/tmp/ip-blocklist.txt"
BLOCKLIST_TMP_FILE="/tmp/ip-blocklist.txt.tmp"

# Create a new MAILLOG from scratch. Do it the very simplest way possible
rm -f $MAILLOG
touch $MAILLOG

echo "" >>$MAILLOG
echo "Downloading the most recent IP list from $TO_DOWNLOAD ..." >>$MAILLOG
wgetOK=$(wget -qO - $TO_DOWNLOAD >> $BLOCKLIST_FILE) >>$MAILLOG 2>&1
if [ $? -ne 0 ]; then
	echo "Most recent IP blocklist could not be downloaded from $TO_DOWNLOAD" >>$MAILLOG
	echo "Please check manually. The script calling this function: $0" >>$MAILLOG
	echo "You can download and import the IP list manually like this:" >>$MAILLOG
	echo "wget -qO - $TO_DOWNLOAD >> /tmp/blocklist-de.txt"
	echo "for i in $( cat /tmp/blocklist-de.txt ); do ipset add $CHAINNAME $i; done" >>$MAILLOG

	### Sending warning e-mail and cancelling the update process
	sudo -u $MAIL_SENDER /usr/bin/mail -s "$MAIL_SUBJECT" $MAIL_RECIPIENTS < $MAILLOG

	### Exit with error in this case
	exit 1
fi

echo "" >>$MAILLOG
echo "Parsing the downloaded file and filter out only IPv4 addresses ..." >>$MAILLOG
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" $BLOCKLIST_FILE > $BLOCKLIST_TMP_FILE

echo "" >>$MAILLOG
echo "Removing duplicate IPs from the list ..." >>$MAILLOG
sort -u $BLOCKLIST_TMP_FILE -o $BLOCKLIST_FILE >>$MAILLOG 2>&1
rm $BLOCKLIST_TMP_FILE

echo "" >>$MAILLOG
echo "Setting up the ipset configuration by creating the '$CHAINNAME' IP set ..." >>$MAILLOG
if [ `$IPSET_PATH list | grep "Name: $CHAINNAME" | wc -l` -eq 0 ]
then
        # Create the new ipset set
	$IPSET_PATH create $CHAINNAME hash:ip maxelem 16777216 >>$MAILLOG 2>&1
else
	echo "ipset configuration already exists - Flushing and recreating the iptables/ipset configuration ..." >>$MAILLOG
	# Reason: The kernel sometimes did not properly flush the ipset list which caused errors. Thus we remove the whole list and recreate it from scatch
	$IPTABLES_PATH --flush $CHAINNAME >>$MAILLOG 2>&1
	$IPSET_PATH flush $CHAINNAME >>$MAILLOG 2>&1
	$IPSET_PATH destroy $CHAINNAME >>$MAILLOG 2>&1
	$IPSET_PATH create $CHAINNAME hash:ip maxelem 16777216 >>$MAILLOG 2>&1
fi

echo "" >>$MAILLOG
echo "Setting up the $CHAINNAME chain on iptables, if required..." >>$MAILLOG
if [ `$IPTABLES_PATH -L -n | grep "Chain $CHAINNAME" | wc -l` -eq 0 ]
then
        # Create the iptables chain
	$IPTABLES_PATH --new-chain $CHAINNAME >>$MAILLOG 2>&1
fi

echo "" >>$MAILLOG
echo "Inserting the new chain $CHAINNAME into iptables INPUT, if required" >>$MAILLOG
# Insert rule (if necesarry) into the INPUT chain so the chain above will also be used
if [ `$IPTABLES_PATH -L INPUT | grep $CHAINNAME | wc -l` -eq 0 ]
then
        # Insert rule because it is not present
	$IPTABLES_PATH -I INPUT -j $CHAINNAME >>$MAILLOG 2>&1
fi

# Create rule (if necesarry) into the $CHAINNAME
echo "" >>$MAILLOG
echo "Creating the firewall rule, if required..." >>$MAILLOG
if [ `$IPTABLES_PATH -L $CHAINNAME | grep REJECT | wc -l` -eq 0 ]
then
	# Create the one and only firewall rule
	$IPTABLES_PATH -I $CHAINNAME -m set --match-set $CHAINNAME src -j $ACTION >>$MAILLOG 2>&1
fi

echo "Adding the return statement to the chain. We do not want to accept a non-matching ip; think about fail2ban" >>$MAILLOG
if [ `$IPTABLES_PATH -L $CHAINNAME | grep RETURN | wc -l` -eq 0 ]
then
	# Create the one and only firewall rule
	$IPTABLES_PATH -A $CHAINNAME -j RETURN >>$MAILLOG 2>&1
fi


## Read all IPs from the downloaded IP list and fill up the ipset filter set
echo "" >>$MAILLOG
echo "Importing the IP list into the IP set..." >>$MAILLOG
for i in $( cat $BLOCKLIST_FILE ); do $IPSET_PATH add $CHAINNAME $i >>$MAILLOG 2>&1; done

echo "" >>$MAILLOG
echo "Done." >>$MAILLOG
if [ "$MAIL" == 1 ]; then sudo -u $MAIL_SENDER $MAIL_PATH -s "SUCCESS - IP blocklist script has updated the IP set with the newest IP list" $MAIL_RECIPIENTS < $MAILLOG; fi;
