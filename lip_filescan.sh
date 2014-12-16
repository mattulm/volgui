#/bin/bash
#
# This scrip is designed to do the basic inistial investigation for a memory image.
# By: Matthew Ulm
# Date: Auguest 8, 2014
#
# This script was built using the SIFT workstation 3.0
# First it will hash the memory file, then dump pslist, pstree, psxview.
# It will then look at the svchost processes, and compare all of them together.
# Then it attempts to dump the svchost processes using procexedump.
# It will then MD5 hash those files, and compare them to some online engines.
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
echo "Welcome to the Lazy Investigator Program. "
echo " "
echo "This particular script will look at the processes found within the memory file. "
echo "First we will pull the process list, then dump the svchost processes. "
echo " "
echo " "
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
echo " "
#
#
# Check for some directories
##############################################################
setupdir=( text evidence filescan )
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
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.process.log
echo "I will take an MD5 hash now";
echo "I will take an MD5 hash now" >> $HOME/$CASE/evidence/$CASE.process.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.process.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";
#
echo "I will take a SHA1 hash now";
echo "I will take a SHA1 hash now" >> $HOME/$CASE/evidence/$CASE.process.log
sha1sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.process.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";
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
echo "Here is the profile being used: $PRFL" >> $HOME/$CASE/evidence/$CASE.process.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";
#
#
# Let's do our process scans to get started on our analysis
##############################################################
cd $HOME/$CASE
$VOL -f $FILE --profile=$PRFL filescan > filescan/filescan.txt
#
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";

#
# Going to parse the file now for some Temp Space things.
cd filescan;
cat filescan.txt | grep -i "tmp" >> filescan.tmp.txt;
cat filescan.txt | grep -i "tmp" | grep -i "dll" >> filescan.tmp.search.txt
echo " " >> filescan.tmp.search.txt; echo " " >> filescan.tmp.search.txt;
echo " " >> filescan.tmp.search.txt; echo " " >> filescan.tmp.search.txt;
cat filescan.txt | grep -i "tmp" | grep -i "exe" >> filescan.tmp.search.txt
cat filescan.txt | grep -i "appdate" >> filescan.appdata.txt;
cat filescan.txt | grep -i "appdata" | grep -i "tmp" >> filescan.appdata.search.txt
echo " " >> filescan.appdata.search.txt; echo " " >> filescan.appdata.search.txt;
echo " " >> filescan.appdata.search.txt; echo " " >> filescan.appdata.search.txt;
cat filescan.txt | grep -i "appdata" | grep -i "dll" >> filescan.appdata.search.txt;
echo " " >> filescan.appdata.search.txt; echo " " >> filescan.appdata.search.txt;
echo " " >> filescan.appdata.search.txt; echo " " >> filescan.appdata.search.txt;
cat filescan.txt | grep -i "appdate" | grep -i "exe" >> filescan.appdate.search.txt
cat filescan.txt | grep -i "temp" >> filescan.temp.txt;



#
# EOF


