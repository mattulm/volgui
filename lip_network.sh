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
DSVT="/home/sansforensics/volgui/tools/dsvtsearch.py"
DSUB="/home/sansforensics/volgui/tools/dsvtsubmit.py"
ADMC="/home/sansforensics/volgui/tools/adobemc.py"
HEADER="Accept: text/html"
UA20="Mozilla/5.0 Gecko/20010527 Firefox/22.3"
UA21="Mozilla/5.0 Gecko/20100114 Firefox/21.1"
UA22="Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.13; ) Gecko/20101203"
TODAY=$(date +"%Y-%m-%d")
FTIME="$(date)"
#
#
### Get some information from the user.
#######################################
#
# Get the case name.
echo "I need to get some information first... "
echo "What is the case name? :"
read CASE
if [ ! -d "$HOME/$CASE" ]; then
        echo "It does not look as if the case has been setup just yet.";
        echo " "; sleep 1; exit;
fi
#
# What is the memory file name
echo "What is the memory file name? :"
read FILE
if [ ! -f "$HOME/$CASE/$FILE" ]; then
        echo "It does not look as if the file you gave me is in the right place.";
        echo "Please make sure the file is in this location. $HOME/$CASE ... ";
        echo " "; sleep 1; exit;
fi
#
#
# Check for some directories
##############################################################
setupdir=( text evidence )
for i in "${setupdir[@]}"; do
	if [ ! -d "$HOME/$CASE/$i" ]; then
		mkdir -p $HOME/$CASE/$i
	fi
done
echo " "
#
### Hash the memory file
#########################
echo "I am going to take some hashes of the memory now. "
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.network.log
echo "I will take an MD5 hash now";
echo "I will take an MD5 hash now" >> $HOME/$CASE/evidence/$CASE.network.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
echo " " >> $HOME/$CASE/evidence/$CASE.network.log; echo " ";
#
echo "I will take a SHA1 hash now";
echo "I will take a SHA1 hash now" >> $HOME/$CASE/evidence/$CASE.network.log
sha1sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
echo " " >> $HOME/$CASE/evidence/$CASE.network.log; 
echo " ";
#
#
### Let's figure out what image we are working with.
### Ask the user if they know what profile to use.
### Find out for them if they do not know.
###########################################################
echo "One last bit of information is needed......"
echo "Do you know what profile to use on this memory sample? (y/n):"
read RESP
case $RESP in
	y|Y )	echo "OK, then......"
        	echo "What profile would you like to use? :"
        	read PRFL;
        	echo " ";;
	n|N )	echo " "
		echo "Let's run our imageinfo module and take a look at what we might have now. "
		vol.py -f $HOME/$CASE/$FILE imageinfo
		# Ask the user what they want to use
		echo "What profile do you want to use for these scans? :"
		read PRFL
		echo " ";;
	* ) 	echo " ";
		echo "That is unexpected input";
		echo "Stopping"
		exit;;
esac
echo " "
echo "Here is the profile being used: $PRFL" >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
echo " "; sleep 1; echo " ";
#
### Start with some basic text files and scans of the memory
### Grab network first so we can start working on that seperatly.
###################################################################
cd $HOME/$CASE/text; mkdir -p $HOME/$CASE/text/ipfiles;
echo "At this time, this script can only perform the netscan operation on a few profiles"
echo "I will add other profiles at a later time as is needed. "
echo " ";
if [ ! -f "$HOME/$CASE/text/netscan.txt" ]; then
	if [ $PRFL = "Win7SP0x86" ]; then
        	echo "I will know grab the network information using the netscan module. $(date) "
		echo "I will know grab the network information using the netscan module. $(date) " >> $HOME/$CASE/evidence/$CASE.network.log
        	$VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
	elif [ $PRFL = "Win7SP1x86" ]; then
		echo "I will know grab the network information using the netscan module. $(date) "
		echo "I will know grab the network information using the netscan module. $(date) " >> $HOME/$CASE/evidence/$CASE.network.log
                $VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
	elif [ $PRFL = "Win7SP0x64" ]; then
		echo "I will know grab the network information using the netscan module. $(date) "
		echo "I will know grab the network information using the netscan module. $(date) " >> $HOME/$CASE/evidence/$CASE.network.log
                $VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
	elif [ $PRFL = "Win7SP1x64" ]; then
		echo "I will know grab the network information using the netscan module. $(date) "
		echo "I will know grab the network information using the netscan module. $(date) " >> $HOME/$CASE/evidence/$CASE.network.log
                $VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
       	else
        	echo "It looks as if the netscan module has already been run."
		echo "It looks as if the netscan module has already been run." >> $HOME/$CASE/evidence/$CASE.network.log
                echo "I am skipping this step for now. "
                sleep 1; echo " ";
        fi
else
        echo "This script can not scan network connections yet for the selected profile"
        echo "Please use the appropriate memory profile script to parse the network date"
fi
echo ""; echo "------------"; echo "";
#
# Let's do some IPv4 parsing. (for now)
if [ -f "$HOME/$CASE/text/netscan.txt" ]; then
	echo "Let's strip out some information from the netscan file now."
	mkdir -p $HOME/$CASE/text/ipfiles;
	cat netscan.txt | egrep -o '(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)' | sort | uniq > ipfiles/ipv4.txt;
	cat netscan.txt | grep LISTENING | awk '{print $3",", $6",", $7}' | egrep -v ":::" | sort | uniq >> ipfiles/ipv4.listening.csv;
	cat netscan.txt | grep CLOSE | awk '{print $3",", $4",", $5",", $6}' | sort | uniq >> ipfiles/ipv4.close.csv;
	cat netscan.txt | grep ESTABLISHED | awk '{print $3",", $4",", $6",", $7","}' | sort | uniq >> ipfiles/ipv4.established.csv;
	#
	# Move into the ipfiles folder.
	cd $HOME/$CASE/text/ipfiles;
	cat ipv4.txt | egrep -v '(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)' | sort | uniq > ipv4.ext.txt;
	echo "This is the number of unique external addresses from the netscan file. ";
	wc -l ipv4.ext.txt;
	echo "Here is the External IPv4 file";
	cat ipv4.ext.txt;
	#
	cat ipv4.txt | egrep '(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)' | sort | uniq > ipv4.int.txt;
	echo "This is the number of unique internal addresses form the netscan file.";
	wc -l ipv4.int.txt;
	echo "Here is the Internal IPv4 file";
	cat ipv4.int.txt;
	#
	# Add this data to our log file.
	echo "Number of unique external addresses from the netscan file. " >> $HOME/$CASE/evidence/$CASE.network.log;
	wc -l ipv4.ext.txt >> $HOME/$CASE/evidence/$CASE.network.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
        echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
	echo "Here is the external IPv4 file results.    " >> $HOME/$CASE/evidence/$CASE.network.log;
	echo "------------------------------------------ " >> $HOME/$CASE/evidence/$CASE.network.log;
	cat ipv4.ext.txt >> $HOME/$CASE/evidence/$CASE.network.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
	#
	echo "Number of unique internal addresses from the netscan file. " >> $HOME/$CASE/evidence/$CASE.network.log;
	wc -l ipv4.int.txt >> $HOME/$CASE/evidence/$CASE.network.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
        echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
	echo "Here is the Internal IPv4 file" >> $HOME/$CASE/evidence/$CASE.network.log;
	echo "--------------------------------- " >> $HOME/$CASE/evidence/$CASE.network.log;
	cat ipv4.int.txt >> $HOME/$CASE/evidence/$CASE.network.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
        echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
	echo " "; echo " "; 
fi
#
# Let's search online for our external IPs
if [ -f "$HOME/$CASE/text/ipfiles/ipv4.ext.txt" ]; then
	cd $HOME/$CASE/text/ipfiles
	mkdir vt vxv phn mcdb wis th mu;
	while read x; do
		wget --header="$HEADER" --user-agent="$UA20" "https://www.virustotal.com/en/ip-address/$x/information/" -O "vt/$x.html"

		wget --header="$HEADER" --user-agent="$UA21" "http://vxvault.siri-urz.net/ViriList.php?IP=$x" -O "vxv/$x.html"

		wget --header="$HEADER" --user-agent="$UA22" "http://www.projecthoneypot.org/ip_$x" -O "phn/$x.html"

		wget --header="$HEADER" --user-agent="$UA20" "http://malc0de.com/database/index.php?search=$x" -O "mcdb/$x.html"

		wget --header="$HEADER" --user-agent="$UA20" "http://who.is/whois-ip/ip-address/$x" -O "wis/$x.html"

               	wget --header="$HEADER" --user-agent="$UA20" "http://totalhash.com/network/ip:$x" -O "th/$x.html"

               	wget --header="$HEADER" --user-agent="$UA21" "http://www.malwareurl.com/ns_listing.php?ip=$x" -O "mu/$x.html"

		sleep 1;
	done < ipv4.ext.txt
fi


#
# As we finish a few more sites in the list, I will work on some parsing rules here
# to help speed up some of the lookup on this section.
cd $HOME/$CASE/text/ipfiles/vt;
for i in *.html; do
	if grep -i "<strong>unknown ip" $i; then 
		rm -rf $i;
	fi
done
echo "Virus Total Result Files to go through" >> $HOME/$CASE/evidence/$CASE.network.log
ls *.html >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
cp *.html $HOME/$CASE/evidence/ 2>/dev/null
#
# Project Honey net
cd $HOME/$CASE/text/ipfiles/phn;
for i in *.html; do
	if grep -iR "<p>We don" $i; then
		rm -rf $i;
	fi
done
echo "Project Honey Net Result Files to go through" >> $HOME/$CASE/evidence/$CASE.network.log
ls *.html >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
cp *.html $HOME/$CASE/evidence/ 2>/dev/null
#
# Malc0de database
cd $HOME/$CASE/text/ipfiles/mcdb;
for i in *.html; do
	if grep -i "yielded no results</br><" $i; then
        	rm -rf $i
	fi
done
echo "Malc0de Result Files to go through" >> $HOME/$CASE/evidence/$CASE.network.log
ls *.html >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
cp *.html $HOME/$CASE/evidence/ 2>/dev/null
#
# VX Vault files
cd $HOME/$CASE/text/ipfiles/vxv;
find -name "*.html" -size -1502 -delete
echo "VX Vault Result Files to go through" >> $HOME/$CASE/evidence/$CASE.network.log
ls *.html >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
cp *.html $HOME/$CASE/evidence/ 2>/dev/null
#
# IP Void Files
cd $HOME/$CASE/text/ipfiles/ipv;
for i in *.html; do
	if grep -i "<h1>Report not found</h1>" $i; then
		rm -rf $i
	fi
done


















#
### Some Spacing for our log file
echo " " >> $HOME/$CASE/evidence/$CASE.network.log; echo " ";
echo " " >> $HOME/$CASE/evidence/$CASE.network.log; echo " ";
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
#
### Hash the memory file
#########################
echo "I am going to take some hashes of the memory now. "
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.network.log
echo "I will take an MD5 hash now";
echo "I will take an MD5 hash now" >> $HOME/$CASE/evidence/$CASE.network.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
echo " " >> $HOME/$CASE/evidence/$CASE.network.log; echo " ";
#
echo "I will take a SHA1 hash now";
echo "I will take a SHA1 hash now" >> $HOME/$CASE/evidence/$CASE.network.log
sha1sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.network.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.log
echo " " >> $HOME/$CASE/evidence/$CASE.network.log;
echo " ";




#
# EOF
