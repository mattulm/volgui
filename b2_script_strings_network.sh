#/bin/bash
#
# This scrip is designed to do the basic inistial investigation for a memory image.
# By: Matthew Ulm
# Date: Auguest 8, 2014
#
### Set some variables
##########################
RDIR="/home/sansforensics";
HOME="/cases";
VOL="vol.py";
DSVT="/home/sansforensics/volgui/tools/dsvtsearch.py";
HEADER="Accept: text/html"
UA21="Mozilla/5.0 Gecko/20100101 Firefox/21.0"
UA22="Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.13; ) Gecko/20101203"
TODAY=$(date +"%Y-%m-%d")
FTIME="$(date)"
#
#
echo " What is the case name? :"
read CASE
echo " "
#
#
# Check a few things first.
if [ ! -d "$HOME/$CASE/text" ]; then
	echo " You have not set up your case yet ";
fi
if [ ! -d "$HOME/$CASE/text/strings" ]; then
	echo " You have not run strings against the memory file yet ";
	echo " "; sleep 1; echo " "; exit;
fi
#
#
#
# Find out what they want to do with the full strings report.
mkdir -p  $HOME/$CASE/text/strings; cd  $HOME/$CASE/text/strings;
#
echo "HTTP Searches...."
cat $HOME/$CASE/text/strings/$CASE.strings.txt | egrep -i 'http|GET|POST|PULL|PUT|html|User-Agent|HTML|HTTP' >> $CASE.strings.http.txt
sleep 1;
#
echo "IRC Searches....."
cat $HOME/$CASE/text/strings/$CASE.strings.txt | egrep -i 'irc|IRC|join|chat|room' >> $CASE.strings.irc.txt
sleep 1;
#
echo "FTP Searches......"
cat $HOME/$CASE/text/strings/$CASE.strings.txt | egrep -i 'ftp' >> $CASE.strings.ftp.txt
sleep 1;
#
echo "Telnet Searches......"
cat $HOME/$CASE/text/strings/$CASE.strings.txt | egrep -i 'telnet' >> $CASE.strings.telnet.txt
sleep 1;
#
echo "SSH 7 SCP Searches ......."
cat $HOME/$CASE/text/strings/$CASE.strings.txt | egrep -i 'ssh|scp' >> $CASE.strings.ssh.txt
sleep 1;
#
echo "IPv4 External Connections ........"
cat $HOME/$CASE/text/strings/$CASE.strings.txt |  grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' | sort | uniq >> $CASE.strings.extipv4.txt
sleep 1;
#
echo "IPv4 Local Connections ......."
cat $HOME/$CASE/text/strings/$CASE.strings.txt | grep -E -v '(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)' | sort | uniq >> $CASE.strings.localippv4.txt
#
#
#
# Here are a series of searches for process DLLs related to networking
echo "Search 1"
cat $CASE.strings.txt | egrep -i 'VirtualAlloc | CreateRemoteThread | SetWindowsHook' >> $CASE.strings.n1.txt
sleep 1;
# 
echo " Search 2"
cat $CASE.strings.txt | egrep -i 'ntdll.dll | wsock32.dll | ws2_32.dll | wininet.dll' >>$CASE.strings.n2.txt
sleep 1;
#
echo "Search 3"
cat $CASE.strings.txt | egrep -i 'iphlpapi.dll | NsiAllocateAndGetTable | nsi.dll | NsiEnumerateObjectsAllParametersEx | NsiEnumerateObjectsAllParameters | netio.sys | nsiproxy.sys | TcpEnumerateConnections | TcpEnumerateListeners' >> $CASE.strings.n3.txt
sleep 1;
#
echo "Search 4"
cat $CASE.strings.txt | egrep -i 'iphlpapi.dll | nsi.dll | netio.sys | nsiproxy.sys | tcpip.sys' >> $CASE.strings.n4.txt
sleep 1;
#
echo "Search 5"
cat $CASE.strings.txt | egrep -i 'InternetOpenUrl | InternetReadFile | HttpSendRequest' >> $CASE.strings.n5.txt
sleep 1;
#
#
#
# Some domain searches
echo "Domain Search 1"
cat $CASE.strings.txt | egrep -i '^[a-zA-Z0-9\-\.]+\.(com|org|net|mil|edu|COM|ORG|NET|MIL|EDU)$' >> $CASE.strings.d1.txt
sleep 1;
#
echo "Deomain Search 2"
cat $CASE.strings.txt | egrep -i '^http\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(/\S*)?$' >> $CASE.strings.d2.txt
sleep 1;
#
echo "Domain Search 3"
cat $CASE.strings.txt | egrep -i '(http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?' >> $CASE.strings.d3.txt
sleep 1;
#
echo "Somain Search 4"
cat $CASE.strings.txt | egrep -i '(?<http>(http:[/][/]|www.)([a-z]|[A-Z]|[0-9]|[/.]|[~])*)'>> $CASE.strings.d4.txt
sleep 1;
#
#cat $CASE.strings.txt | egrep -i '^(http|https|ftp)\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~])*$' >>


#
# EOF
