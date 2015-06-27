#/bin/bash
#
# This script is designed to do the basic initial investigation for a memory image.
# By: Matthew Ulm
# Date: June 26, 2015
#
### Set some variables
##########################
USER="/home/sansforensics";
HOME="/cases";
VOL="vol.py";
DSVT="/home/sansforensics/volgui/tools/dsvtsearch.py"
DSUB="/home/sansforensics/volgui/tools/dsvtsubmit.py"
ADMC="/home/sansforensics/volgui/tools/adobemc.py"
HEADER="Accept: text/html"
UA20="Mozilla/5.0 Gecko/20010527 Firefox/22.3"
TODAY=$(date +"%Y-%m-%d")
FTIME="$(date)"
#
#
### Get some information from the user.
#######################################
# 
echo "This particular script will look at the chromees found within the memory file. "
echo "First we will pull the chrome list after hashing the memory image "
echo "Then I will dump the chrome chromees, and compare those to each other. "
echo " "
echo " "
#
# SECTION 00
# Get Information from the USER
#
# Get the case name from the user.
echo "I need to get some information first... "
echo "What is the case name?"
echo "For me this is the folder name in the cases folder.....:"
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
        echo " "; 
	echo "Please check the file lcoation, and try the script again."
	exit;
fi
echo " "
echo "What is your Virus Total API Key "
read APIK
#
#############################################################
#
# SECTION 01
#	Administrative Setup and checks for the script
#
# Check for some directories
#
if [ ! -d "$HOME/$CASE/text" ]; then
	echo "We seem to be missing a few files and folders needed"
	echo "In order to make this script work properly"
	echo ""; sleep 1;
	echo "For now I am going to exit."
	echo "Make sure you run the scripts in the right order"
	exit;
fi
done
echo " "
#
#
# Hash the memory file
echo "I am going to take some hashes of the memory now. ";
echo "I am going to take some hashes of the memory now. " >> $HOME/$CASE/evidence/$CASE.chrome.log;
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
echo "------------------------------------------------------------"
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.chrome.log
echo "The file being analyzed is: $FILE ";
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.chrome.log;
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
echo "------------------------------------------------------------"
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.chrome.log
#
# MD5 hash first
echo "I will first take an MD5 hash now";
echo "I will first take an MD5 hash now" >> $HOME/$CASE/evidence/$CASE.chrome.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.chrome.log
echo "------------------------------------------------------------"
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.chrome.log
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
#
# Now time for the SHA1 hash.
echo "I will take a SHA1 hash now";
echo "I will take a SHA1 hash now" >> $HOME/$CASE/evidence/$CASE.chrome.log
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
sha1sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.chrome.log
echo "------------------------------------------------------------"
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.chrome.log
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
#
# Now time for the SHA256 hash.
echo "I will take a SHA256 hash now";
echo "I will take a SHA256 hash now" >> $HOME/$CASE/evidence/$CASE.chrome.log
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
sha256sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.chrome.log
echo "------------------------------------------------------------"
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.chrome.log
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
#
echo "Here are the hashes from the chrome module run: " >> $HOME/$CASE/evidence/memory.hash.list
cat $HOME/$CASE/evidence/$CASE.chrome.log >> $HOME/$CASE/evidence/memory.hash.list
echo "" >> $HOME/$CASE/evidence/memory.hash.list
echo "" >> $HOME/$CASE/evidence/memory.hash.list
#
##################################################################
#
# SECTION 02
#	First runs at the memory file.
#
# Let's figure out what image we are working with.
# Ask the user if they know what profile to use.
# Find out for them if they do not know.
#
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
echo " ";
echo "This is the profile being used: $PRFL" >> $HOME/$CASE/evidence/$CASE.chrome.log;
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.chrome.log;
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " "; echo " ";
#
#
# Let's do our chrome scans to get started on our analysis
# First move into our CASE directory
cd $HOME/$CASE
#
#
####################################################################
# SECTION 03
#	Let's do First start by looking at our chrome chrome.
#
cd $HOME/$CASE/text;
cat pslist.txt | grep chrome | awk '{ print $3 }' >> chrome.pids.list.working
cat pslist.txt | grep chrome | awk '{ print $4 }' >> chrome.parent.list.working
cat psscan.txt | grep chrome | awk '{ print $3 }' >> chrome.pids.list.working
cat psscan.txt | grep chrome | awk '{ print $4 }' >> chrome.parent.list.working
cat chrome.pids.list.working | sort -u >> chrome.pids.list
cat chrome.parent.lists.working | sort -u >> chrome.parent.list
rm -rf chrome.pids.list.working 
rm -rf chrome.parent.lists.working
#
# Let's print information about the chrome chromees found.
ChromePIDs=($(wc -l chrome.pids.list))
echo "There were $ChromePIDs chrome process(es) discovered within RAM."
echo "There were $ChromePIDs chrome process(es) discovered within RAM." >> $HOME/$CASE/evidence/$CASE.chrome.log
echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
echo "Here ( is - are ) all of the chrome PIDs ";
cat chrome.pids.list; echo " "; sleep 3;   
# The sleep is to give you some time to read it.
# Now to the log file.
echo "Here ( is - are ) all of the chrome PIDSs " >> $HOME/$CASE/evidence/$CASE.chrome.log
cat chrome.pids.list >> $HOME/$CASE/evidence/$CASE.chrome.log
#
#
# Work with the SVChost parent chromees
ChromePPIDs=($(wc -l chrome.parent.list))
echo "There were $ChromePPIDs unique chrome parent process(es) "
echo "There were $ChromePPIDs unique chrome parent process(es) " >> $HOME/$CASE/evidence/$CASE.chrome.log
echo " " >> $HOME/$CASE/evidence/$CASE.log; echo " ";
echo "Here ( is - are ) the chrome parent(s) processes.... ";
cat chrome.parent.list; echo " "; echo " "; sleep 3;
# the sleep is to give you time to read it.
# Now for the log file again.
echo "Here ( is - are ) the chrome parent(s) processes.... "; >> $HOME/$CASE/evidence/$CASE.chrome.log
cat chrome.parent.list >> $HOME/$CASE/evidence/$CASE.chrome.log
#
#
cd $HOME/$CASE/pdump; 
mkdir chrome;
while read r; do
	$VOL -f $HOME/$CASE/$FILE --profile=$PRFL procdump -p $r -D chrome
done < chrome.pids.list
#
cd chrome;
for i in *.exe; do
	md5sum $i >> chrome.md5.full
	sha1sum $i >> chrome.sha1.full
	sha256sum $i >> svchosr.256.full
done
#
#
cat chrome.md5.full | cut -c 1-32 | sort -u >> chrome.md5.list
cat chrome.sha1.full | cut -c 1-40 | sort -u >> chrome.sha1.list
cat chrome.256.full | cut -c 1-64 | sort -u >> chrome.256.list
#
#
cat chrome.md5.list >> $HOME/$CASE/evidence/$CASE.md5.list;
cat chrome.md5.full >> $HOME/$CASE/evidence/$CASE.md5.full;
cat chrome.sha1.list >> $HOME/$CASE/evidence/$CASE.sha1.list;
cat chrome.sha1.full >> $HOME/$CASE/evidence/$CASE.sha1.full;
cat chrome.256.list >> $HOME/$CASE/evidence/$CASE.256.list;
cat chrome.256.full >> $HOME/$CASE/evidence/$CASE.256.full;
#
#
# Let's do some stuff online now.
# ## Will need to make some directories, and files and what not.
#
# Thes are for the MD5 hashes.
mkdir vxv te th mdb;
echo "Going to check the MD5 hashes online now. ";
echo "Going to check the MD5 hashes online now. " >>  $HOME/$CASE/evidence/$CASE.chrome.log;
while read r; do
	# trying to keep the timing around to 20 seconds for a hash.
	sleep 1;
	echo "Check $r with VX Vault.....";
	echo "Check $r with VX Vault....." >> $HOME/$CASE/evidence/$CASE.chrome.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.chrome.md5.log;
	wget --header="$HEADER" --user-agent="$UA20" "http://vxvault.siri-urz.net/ViriList.php?MD5=$r" -O "vxv/$r.vxv.html"
	sleep 5;
	echo "Check $r with Threat Expert.....";
	echo "Check $r with Threat Expert....." >> $HOME/$CASE/evidence/$CASE.chrome.log;
	wget --header="$HEADER" --user-agent="$UA20" "http://www.threatexpert.com/report.aspx?md5=$r" -O "te/$r.te.html"
	echo " " >> $HOME/$CASE/evidence/$CASE.chrome.md5.log;
	sleep 4;
	echo "Check with Total Hash.....";
	echo "Check with Total Hash....." >> $HOME/$CASE/evidence/$CASE.chrome.log;
	wget --no-check-certificate --header="$HEADER" --user-agent="$UA20" "http://totalhash.com/search/hash:$r" -O "th/$r.th.html"
	echo " " >> $HOME/$CASE/evidence/$CASE.chrome.md5.log;
	sleep 5;
	echo "Check with Malware DB ......";
	echo "Check with Malware DB ......" >> $HOME/$CASE/evidence/$CASE.chrome.log;
	wget --header="$HEADER" --user-agent="$UA20" "http://malwaredb.malekal.com/index.php?hash=$r" -O "mdb/$r.mdb.html"
	echo " " >> $HOME/$CASE/evidence/$CASE.chrome.md5.log;
done < chrome.md5.list
python $DSVT -k $APIK -f chrome.md5.list;
#
#
# Let's look through some of the SHA 256 hashes now. 
# For VT we are going to go a bit slower on these files.
mkdir vt_256;
echo "Going to check the SHA 256 hashes super quick.";
echo "Going to check the SHA 256 hashes super quick." >> $HOME/$CASE/evidence/$CASE.chrome.log;
while read r; do
	echo "Check $r with Virus Total ......";
	echo "Check $r with Virus Total ......" >> $HOME/$CASE/evidence/$CASE.chrome.log;
	wget --header="$HEADER" --user-agent="UA20" "https://www.virustotal.com/en/file/$variable/analysis/" -O "vt_256/$r.vt_256.html"
	sleep 20;
done < chrome.256.list;
#

#
#
# TO DO:
# Need to include some file parsing here so we can remove hashes that have no hits.
# Also should look at including the other hash sets.
ssdeep -b -a -p *.exe >> $HOME/$CASE/pdump/chrome/ssdeep.chrome.log;
cat $HOME/$CASE/pdump/chrome/ssdeep.chrome.log >> $HOME/$CASE/evidence/$CASE.chrome.log;
cat $HOME/$CASE/pdump/chrome/ssdeep.chrome.log;
echo " "; sleep 3; echo " ";
#
#
for i in *.exe; do
	echo "-----------------------------------" >> $HOME/$CASE/evidence/$CASE.chrome.log
	file $i >> $HOME/$CASE/evidence/$CASE.chrome.log;
	# /usr/local/bin/pescan $i >> $HOME/$CASE/evidence/$CASE.chrome.log;
	# echo " " >> $HOME/$CASE/evidence/$CASE.chrome.chrome.log;
	echo "Adobe Malware CLassifier....." >> $HOME/$CASE/evidence/$CASE.chrome.log;
	python $ADMC -f $i -n 1 >> $HOME/$CASE/evidence/$CASE.chrome.log;
	python $ADMC -f $i -n 2 >> $HOME/$CASE/evidence/$CASE.chrome.log;
	python $ADMC -f $i -n 3 >> $HOME/$CASE/evidence/$CASE.chrome.log;
	python $ADMC -f $i -n 4 >> $HOME/$CASE/evidence/$CASE.chrome.log;
        python $ADMC -f $i >> $HOME/$CASE/evidence/$CASE.chrome.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log;
	strings -a -e l $i >> $i.strings
	echo "----------" >> $i.strings; echo "----------" >> $i.strings;
	strings -a -e b $i >> $i.strings;
	echo "----------" >> $i.strings; echo "----------" >> $i.strings;
	strings -a $i >> $i.strings;
done
#
#
#
#
#
##########################################################
#
# SECTION 04


# Run pstree to get some command lines

 





ChromeStuff=( chromecookies chromedownloadchains chromedownloads chromehistory chromevisits chromesearchterms )
for i in "${ChromeStuff[@]}"; do
	if [ ! -f "$HOME/$CASE/pdump/chrome/$i.txt" ]; then
		echo "$i module has been run at $(date), against the memory file."
        echo "$i module has been run at $(date), against the memory file." >> $HOME/$CASE/evidence/$CASE.chrome.log
		echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo "";
		$VOL -f $FILE --profile=$PRFL $i > text/$i.txt
		echo " " >> $HOME/$CASE/evidence/$CASE.chrome.log; echo " ";
		sleep 1;
	else 
		echo "It looks as if the $i module has already been run."
		echo "I am skipping this step for now. "
		sleep 1; echo " ";
	fi
done


#
# Lets look for more of the SANS Find Evil poster.





#
# EOF
