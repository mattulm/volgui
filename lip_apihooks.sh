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
setupdir=( text apihooks )
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
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.apihooks.log
echo "I will take an MD5 hash now";
echo "I will take an MD5 hash now" >> $HOME/$CASE/evidence/$CASE.apihooks.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.apihooks.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.apihooks.log
echo " " >> $HOME/$CASE/evidence/$CASE.apihooks.log; echo " ";
#
echo "I will take a SHA1 hash now";
echo "I will take a SHA1 hash now" >> $HOME/$CASE/evidence/$CASE.apihooks.log
sha1sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.apihooks.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.apihooks.log
echo " " >> $HOME/$CASE/evidence/$CASE.apihooks.log; echo " ";
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
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.process.log
echo " " >> $HOME/$CASE/evidence/$CASE.process.log; echo " ";
#
#
# Let's run the apihooks plugin, and do some analysis
##############################################################
cd $HOME/$CASE
$VOL -f $FILE --profile=$PRFL apihooks >> apihooks/apihooks.txt
cd $HOME/$CASE/apihooks;

#
# Analysis Time
cat apihooks.txt | grep -B4 unknown | grep Process | grep -v Function | awk '{print $2}' | sort | uniq >> apihooks.jmp.pids.txt
	# -B4 four lines before we see the unknown flag
	# From those results look for the Process
	# only print the second column which is the PID
	# sort, then only take the uniqs.
mkdir exedump;
while read r; do
	$VOL -f $HOME/$CASE/$FILE --profile=$PRFL procexedump -p $r -D exedump
done < apihooks.jmp.pids.txt
#
cat apihooks.txt | grep JMP | grep -v EDX | grep -v DWORD | awk '{print $4}' | sort | uniq >> apihooks.jmp.a1.txt 
cat apihooks.txt | grep JMP | grep -v EDX | grep -v DWORD | awk '{print $1}' | sort | uniq >> apihooks.jmp.a2.txt
#
#
cd exedump;
for i in *.exe; do
	strings -a -e l $i >> $i.strings
	echo " " >> $i.strings; echo " " >> $i.strings;
	echo "------------------------------" >> $i.strings
	strings -a -e b $i >> $i.strings
	echo " " >> $i.strings; echo " " >> $i.strings;
	echo "------------------------------" >> $i.strings
	strings -a $i >> $i.strings
done
#
for i in *.exe; do
        echo "-------------------------" >> apihooks.results.txt;
        file $i >> apihooks.results.txt;
        /usr/local/bin/pescan $i >> apihooks.results.txt;
        echo " " >> apihooks.results.txt;
        echo "Adobe Malware CLassifier....." >> apihooks.results.txt;
        python $ADMC -f $i -n 1 >> apihooks.results.txt;
        python $ADMC -f $i -n 2 >> apihooks.results.txt;
        python $ADMC -f $i -n 3 >> apihooks.results.txt;
        python $ADMC -f $i -n 4 >> apihooks.results.txt;
        python $ADMC -f $i >> apihooks.results.txt;
        echo " " >> apihooks.results.txt;
        echo " " >> apihooks.results.txt;
done


#
# EOF
