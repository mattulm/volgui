#!/bin/bash
#
#
#
HEADER="Accept: text/html"
UA20="Mozilla/5.0 Gecko/20010527 Firefox/22.3"
UA21="Mozilla/5.0 Gecko/20100114 Firefox/21.1"
UA22="Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.13; ) Gecko/20101203"

#
# Get the IP address from the user
echo "What IP would you like to lookup? : "
read IPADDR
mkdir $IPADDR; cd $IPADDR;

#
# malc0de Database
wget --header="$HEADER" --user-agent="$UA21" "http://malc0de.com/database/index.php?search=$IPADDR" -O "mcdb.html"
wget --header="$HEADER" --user-agent="$UA22" "https://www.virustotal.com/en/ip-address/$IPADDR/information/" -O "vt.html"
wget --header="$HEADER" --user-agent="$UA21" "http://vxvault.siri-urz.net/ViriList.php?IP=$IPADDR" -O "vxv.html"
wget --header="$HEADER" --user-agent="$UA22" "http://www.projecthoneypot.org/ip_$IPADDR" -O "phn.html"

#
#
if grep -q "yielded no results" mcdb.html; then
        echo "The Malc0de database has no information about this IP address. "
        rm -rf mcdb.html
fi
#
#
if grep -q "<strong>unknown ip" vt.html; then
        echo "Virus Total has no information about this IP."
        rm -rf vt.html
fi
#
#
if grep -q "<p>We don" phn.html; then
        echo "Project Honey Net has no infomation about this IP. "
        rm -rf phn.html
fi
#
#
#
#
echo " "; echo " "; echo " ";

