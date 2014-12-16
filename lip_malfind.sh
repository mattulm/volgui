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
echo "What is your Virus Total API Key "
read APIK
#
#
# Check for some directories
##############################################################
setupdir=( malfind dlldump vaddump )
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
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.malfind.log
echo "I will take an MD5 hash now";
echo "I will take an MD5 hash now" >> $HOME/$CASE/evidence/$CASE.malfind.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.malfind.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.network.malfind.log
echo " " >> $HOME/$CASE/evidence/$CASE.malfind.log; echo " ";
#
echo "I will take a SHA1 hash now";
echo "I will take a SHA1 hash now" >> $HOME/$CASE/evidence/$CASE.malfind.log
sha1sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.malfind.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.malfind.log
echo " " >> $HOME/$CASE/evidence/$CASE.malfind.log; echo " ";
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
#
#
# Running the malfind plugin
cd $HOME/$CASE;
$VOL -f $FILE --profile=$PRFL malfind --dump-dir malfind >> $HOME/$CASE/malfind/malfind.txt
echo "Done runing the malfind plugin. "
echo "I will now go through those results a little bit. "
cd $HOME/$CASE/malfind;
cat malfind.txt | grep -B4 MZ | grep "Pid:" | cut -f 3 -d":" | cut -f 2 -d" " >> malfind.pids.list
echo "Here are the injected executables identified by Malfind plugin."
echo "Here are the injected executables identified by Malfind plugin." >> $HOME/$CASE/evidence/malfind.results.txt;
cat malfind.pids.list; echo " "; sleep 1; echo " ";
cat malfind.pids.list >> $HOME/$CASE/evidence/malfind.results.txt;
echo " " >> $HOME/$CASE/evidence/malfind.results.txt; echo " " >> $HOME/$CASE/evidence/malfind.results.txt;
#
file *.dmp | egrep '(PE32|COM)' | cut -f 1 -d":" | wc -l >> malfind.pe32.count
echo "Here is the PE32 count from the malfind plugin" 
cat  malfind.pe32.count
echo "Here is the PE32 count from the malfind plugin" >> $HOME/$CASE/evidence/malfind.results.txt;
cat  malfind.pe32.count >> $HOME/$CASE/evidence/malfind.results.txt;
echo " " >> $HOME/$CASE/evidence/malfind.results.txt; echo " " >> $HOME/$CASE/evidence/malfind.results.txt;
#
file *.dmp | egrep '(PE32|COM)' | cut -f 1 -d":" >> malfind.pe32.list
echo "Here is the malfind PE32 count"
cat malfind.pe32.list
echo " "; sleep1; echo " ";
echo "Here is the malfind PE32 count" >> $HOME/$CASE/evidence/malfind.results.txt;
cat malfind.pe32.list >> $HOME/$CASE/evidence/malfind.results.txt;
#
echo " "; echo " ";
#
# Going through the malfind files now
# Some PE file tools, and strings.
cd $HOME/$CSE/malfind;
LINE=$( wc -l malfind.pe32.list | cut -f 1 -d" " )
if [ $LINE -eq 0 ]; then
	echo "According to malfind, there are no injected processes identified, with the "
	echo "malfind plugin. We will skip a few steps, and dig right into our modules "
	echo "section. "
	echo " ";
else
	echo "I am going to use a few tools against the files. This could take some time. "
	while read w; do
		echo "-------------------------------------------------------" >> $HOME/$CASE/malfind.results.txt
		file $w >> $HOME/$CASE/evidence/malfind.results.txt
		echo " " >> $HOME/$CASE/evidence/malfind.results.txt
		/usr/local/bin/pescan $w >> $HOME/$CASE/evidence/malfind.results.txt
		echo " " >> $HOME/$CASE/evidence/malfind.results.txt
		python $ADMC -f $w -n 1 >> $HOME/$CASE/evidence/malfind.results.txt
		python $ADMC -f $w -n 2 >> $HOME/$CASE/evidence/malfind.results.txt
		python $ADMC -f $w -n 3 >> $HOME/$CASE/evidence/malfind.results.txt
		python $ADMC -f $w -n 4 >> $HOME/$CASE/evidence/malfind.results.txt
		python $ADMC -f $w >> $HOME/$CASE/evidence/malfind.results.txt
		echo " " >> $HOME/$CASE/evidence/malfind.results.txt
                echo " " >> $HOME/$CASE/evidence/malfind.results.txt
	done < malfind.pe32.list
fi
#
for i in *.dmp; do
	md5sum $i >> malfind.md5.list
done
cat malfind.md5.list | cut -c 1-32 | sort | uniq >> malfind.md5
#
mkdir te vxv vt;
while read i; do
	wget --header="$HEADER" --user-agent="$UA22" http://www.threatexpert.com/report.aspx?md5=$i -O "te/$i.html"
	wget --header="$HEADER" --user-agent="$UA22" http://vxvault.siri-urz.net/ViriList.php?MD5=$i -O "vxv/$i.html"
done < malfind.md5
#
#
# Grab the strings from any injected executable according to malfind.
if [ $LINE -eq 0 ]; then
	echo "Skipping a few more tools. "
else 
	echo "I am going to run strings against all of the injected executables "
	echo "identified by the malfind plugin run earlier. "
	echo " "
	while read p; do
		echo "Command Run: strings -a -e l" >> $p.strings;
		strings -a -e l $p >> $p.strings;
		echo " " >> $p.strings; echo " " >> $p.strings;
		echo "-----------------------------------------------" >> $p.strings;
		echo "Command Run: strings -a -e b" >> $p.strings;
		strings -a -e b $p >> $p.strings;
	        echo " " >> $p.strings; echo " " >> $p.strings;
	        echo "-----------------------------------------------" >> $p.strings;
		echo "Command Run: strings -a" >> $p.strings;
		strings -a $p >> $p.strings;
	done < malfind.pe32.list
	echo " "; echo "-----"; echo " ";
fi
#
# Dump the VAD for the injected files as well
cd $HOME/$CASE
while read t; do
	vol.py -f $FILE --profile=$PRFL vaddump --dump-dir vaddump -p $t >> vaddump/vaddump.$t.txt
done < $HOME/$CASE/malfind/malfind.pids.list
echo " "; echo "-----"; echo " ";
#
cd vaddump;
for i in *.dmp; do
	file $i | egrep '(PE32|COM)' | cut -f 1 -d":" >> vaddump.pe32.list
done;
#
while read e; do
	md5sum $e >> vaddump.md5.list
done < vaddump.pe32.list
#
cat vaddump.md5.list | cut -c 1-32 | sort | uniq >> vaddump.md5
mkdir t3 vxv th vt
while read q; do
        wget --header="$HEADER" --user-agent="$UA22" http://www.threatexpert.com/report.aspx?md5=$q -O "te/$q.html"
        wget --header="$HEADER" --user-agent="$UA22" http://vxvault.siri-urz.net/ViriList.php?MD5=$q -O "vxv/$q.html"
done < vaddump.md5

LINE=$( wc -l vaddump.pe32.list | cut -f 1 -d" " )
if [ $LINE -eq 0 ]; then
        echo "According to malfind, there are no injected processes identified, with the "
        echo "malfind plugin. We will skip a few steps, and dig right into our modules "
        echo "section. "
        echo " ";
else
        echo "I am going to use a few tools against the files. This could take some time. "
        while read w; do
                echo "-------------------------------------------------------" >> $HOME/$CASE/malfind.results.txt
                file $w >> $HOME/$CASE/evidence/malfind.results.txt
                echo " " >> $HOME/$CASE/evidence/malfind.results.txt
                /usr/local/bin/pescan $w >> $HOME/$CASE/evidence/malfind.results.txt
                echo " " >> $HOME/$CASE/evidence/malfind.results.txt
                python $ADMC -f $w -n 1 >> $HOME/$CASE/evidence/malfind.results.txt
                python $ADMC -f $w -n 2 >> $HOME/$CASE/evidence/malfind.results.txt
                python $ADMC -f $w -n 3 >> $HOME/$CASE/evidence/malfind.results.txt
                python $ADMC -f $w -n 4 >> $HOME/$CASE/evidence/malfind.results.txt
                python $ADMC -f $w >> $HOME/$CASE/evidence/malfind.results.txt
                echo " " >> $HOME/$CASE/evidence/malfind.results.txt
                echo " " >> $HOME/$CASE/evidence/malfind.results.txt
        done < vaddump.pe32.list
fi




#
# EOF




