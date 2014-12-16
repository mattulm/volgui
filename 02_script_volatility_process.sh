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
# Get the case name from the user
echo "What is the case name? :"
read CASE
# What is the memory file name
echo "What is the memory file name? :"
read FILE
#
# 
# Checking for these things needs to be written yet.
mkdir -p $HOME/$CASE/evidence
mkdir -p $HOME/$CASE/text
cd $HOME/$CASE;
#
# Add to the log file
echo "Today is $TODAY. "
echo "Today is $FTIME. " >> $HOME/$CASE/evidence/$CASE.log
echo "This script is meant to pull information about a particular process."
echo "This script is meant to pull information about a particular process." >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo "Today is $(date)" >> $HOME/$CASE/evidence/$CASE.log
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.log
echo "I am going to take an MD5 sum of the file now. "
echo "I am going to take an MD5 sum of the file now. " >> $HOME/$CASE/evidence/$CASE.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.log
echo " "; sleep 1; echo " ";
echo "I am going to take a SHA 1 sum of the file now. "
echo "I am going to take a SHA 1 sum of the file now. " >> $HOME/$CASE/evidence/$CASE.log
sha1sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo " "; sleep 1; echo " "; 
#
# What is the profile
echo "What is the profile? :"
read PRFL
#
# Get the process number from the user
echo "What process do you want to look at? :"
read NMBR
mkdir -p procpulls/$NMBR
#
#
# Print some stuff to the screen. 
echo " I will know pull some information from the memory sample "
echo " "
cd procpulls/$NMBR;
#
# Run the scans on the input files
echo "Today is $FTIME. " >> $HOME/$CASE/evidence/$CASE.$NMBR.log
echo "This script is meant to pull information about a particular process." >> $HOME/$CASE/evidence/$CASE.$NMBR.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.$NMBR/log
singleprocpull=( dlldump vaddump malfind memdump )
for i in "${singleprocpull[@]}"; do
        if [ ! -d "$i" ]; then
                mkdir -p $i
        else
                echo "I see the $i directory already present "
                echo " "; sleep 1;echo " ";
        fi
done
echo " "
#
#
for i in "${singleprocpull[@]}" do
	cd $HOME/$CASE/procpulls/$NMBR/$i; echo $i;
        vol.py -f $HOME/$CASE/$FILE --profile=$PRFL $i -p $NMBR -D $i 
	echo "Copleted the $i on process $NMBR at $FTIME."
	echo "Copleted the $i on process $NMBR at $FTIME." >> $HOME/$CASE/evidence/$CASE.$NMBR.log
	echo " "; sleep 1; echo " "; echo " " >> $HOME/$CASE/evidence/$CASE.$NMBR.log
done
#
#
#
#
#
#
# Let's do some vaddump work now on our files.
cd $HOME/$CASE/procpulls/$NMBR/vaddump;
for i in *.dmp; do file $i >> vaddump.file.w.txt; done
cat vaddump.file.w.txt | grep PE32 | awk '{ print $1 }' | cut -c 1-46 >> vaddump.file.pe32.txt;
while read p; do
	md5sum $p >> vaddump.file.pe.md5.txt
done < vaddump.file.pe32.txt
cat vaddump.file.pe.md5.txt | cut -c 1-32 >> vaddump.file.md5.txt;
#
# Pull the  code for the Didier Stevens uploads, and/or searches.
#
#
#
#
#
cd $HOME/$CASE/procpulls/$NMBR;
singleproctext=( dlllist apihooks callbacks ldrmodules ssdt )
for i in "${singleproctext[@]}"
do
	echo $i
	vol.py -f $HOME/$CASE/$FILE --profile=$PRFL $i -p $NMBR >> $i.$NMBR.txt
	echo "Completed the $i pull on process $NMBR at $FTIME. ";
        echo "Copleted the $i on process $NMBR at $FTIME."
        echo "Copleted the $i on process $NMBR at $FTIME." >> $HOME/$CASE/evidence/$CASE.$NMBR.log
	echo " "; sleep 1; echo " "; echo " " >> $HOME/$CASE/evidence/$CASE.$NMBR.log
done

#
# Print some stuff to the screen.
echo " I am done pulling text based information. "
echo " You can start going through those for pertinent data. "
echo " "
echo " In the meantime I will pull the DLLs for this process. "
echo " and do a similar comparison wiht the process dumper routine "
echo " "
#
#
#
#
#
# Let's work with the dlllist output now.
cd $HOME/$CASE/procpulls/$NMBR;
cat dlllist.$NMBR.txt | grep -i -v system32 >> dlllist.$NMBR.nosys32.txt
echo "I have pulled out the System32 DLLs now. ";
echo " "; sleep 1; echo " ";







# 
# EOF
