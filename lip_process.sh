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
echo "What is your Virus Total API Key "
read APIK
#
#
# Check for some directories
##############################################################
setupdir=( text evidence procexedump )
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
process=( pslist psxview pstree )
for i in "${process[@]}"; do
	if [ ! -f "text/$i.txt" ]; then
		echo "$i module has been run at $(date), against the memory file."
                echo "$i module has been run at $(date), against the memory file." >> $HOME/$CASE/evidence/$CASE.process.log
		$VOL -f $FILE --profile=$PRFL $i > text/$i.txt
		echo " "; sleep 1; echo "";
	else 
		echo "It looks as if the $i module has already been run."
		echo "I am skipping this step for now. "
		sleep 1; echo " ";
	fi
done
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";
#
# Looking for svchost with this section.
cd $HOME/$CASE/text;
cat pslist.txt | grep 0x | grep svchost | awk '{ print $3 }' > svchost.pids.list
cat pslist.txt | grep 0x | grep svchost | awk '{ print $4 }' > svchost.parent.list
cat pslist.txt | grep -v DagentConfig | grep -v dagentui | grep -v "net.exe" > pslist.noaltiris.txt
cat pstree.txt | grep -v DagentConfig | grep -v dagentui | grep -v "net.exe" > pstree.noaltiris.txt
#
#
SVCHC=($(wc -l svchost.pids.list))
echo "There are $SVCHC svchost processes discovered within RAM."
echo "There are $SVCHC svchost processes discovered within RAM." >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";
echo "Here are all of the svchost PIDs ";
cat svchost.pids.list; echo " "; echo " "; sleep 3;
echo "Here are all of the svchost PIDSs " >> $HOME/$CASE/evidence/$CASE.process.log
cat svchost.pids.list >> $HOME/$CASE/evidence/$CASE.process.log
#
cat svchost.parent.list | sort | uniq > svchost.parent
SVCPC=($(wc -l svchost.parent))
echo "There ( is - are ) $SVCPC unique svchost parent processes"
echo "There ( is - are ) $SVCPC unique svchost parent processes" >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.log; echo " ";
echo "Here is the svchost parent(s) processes.... ";
cat svchost.parent; echo " "; echo " "; sleep 1;
echo "Here is the svchost parent(s) processes.... "; >> $HOME/$CASE/evidence/$CASE.process.log
cat svchost.parent >> $HOME/$CASE/evidence/$CASE.process.log
echo "Here ( is - are ) the svchost parent(s) processes....." 
echo "Here ( is - are )the svchost parent(s) processes.... " >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.process.log
#
#
# Trying to pull the memory offsets from a few of the process lists.
# THe thought is to pull these, and use them to pull the executables seperately.
# from teh PID file, as a means to check for process hallowing.
cd $HOME/$CASE/text; mkdir svchost;
while read r; do
	$VOL -f $HOME/$CASE/$FILE --profile=$PRFL procexedump -p $r -D svchost
done < svchost.pids.list
#
cd svchost
for i in *.exe; do
	md5sum $i >> svchost.md5sum.list
done
cat svchost.md5sum.list | cut -c 1-32 | sort | uniq >> svchost.md5
echo "Going to check these hashes online now. ";
while read r; do
	wget --header="$HEADER" --user-agent="$UA21" "http://vxvault.siri-urz.net/ViriList.php?MD5=$r" -O "$r.vxv.html"
	wget --header="$HEADER" --user-agent="$UA20" "http://www.threatexpert.com/report.aspx?md5=$r" -O "$r.te.html"
	wget --header="$HEADER" --user-agent="$UA21" "http://totalhash.com/search/hash:$r" -O "$r.th.html"
done < svchost.md5
python $DSVT -k $APIK -f svchost.md5
#
# Need to include some file parsing here so we can remove hashes that have no hits.
#
#
ssdeep -b -a -p *.exe >> $HOME/$CASE/evidence/$CASE.process.log
ssdeep -b -a -p *.exe
echo " "; sleep 3; echo " ";
#
#
for i in *.exe; do
	echo "-----------------------------------" >> $HOME/$CASE/evidence/$CASE.process.log
	file $i >> $HOME/$CASE/evidence/$CASE.process.log;
	/usr/local/bin/pescan $i >> $HOME/$CASE/evidence/$CASE.process.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.process.log;
	echo "Adobe Malware CLassifier....." >> $HOME/$CASE/evidence/$CASE.process.log;
	python $ADMC -f $i -n 1 >> $HOME/$CASE/evidence/$CASE.process.log;
	python $ADMC -f $i -n 2 >> $HOME/$CASE/evidence/$CASE.process.log;
	python $ADMC -f $i -n 3 >> $HOME/$CASE/evidence/$CASE.process.log;
	python $ADMC -f $i -n 4 >> $HOME/$CASE/evidence/$CASE.process.log;
        python $ADMC -f $i >> $HOME/$CASE/evidence/$CASE.process.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.process.log;
	echo " " >> $HOME/$CASE/evidence/$CASE.process.log;
	strings -a -e l $i >> $i.strings
	echo "----------" >> $i.strings; echo "----------" >> $i.strings;
	strings -a -e b $i >> $i.strings;
	echo "----------" >> $i.strings; echo "----------" >> $i.strings;
	strings -a $i >> $i.strings;
done
#
# Run pstree to get some command lines
cd $HOME/$CASE
$VOL -f $FILE --profile=$PRFL pstree -v >> text/pstree.verbose.txt



#
# Lets look for more of the SANS Find Evil poster.





#
# EOF
