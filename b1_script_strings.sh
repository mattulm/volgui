#!/bin/bash
#
# Just some basic strings stuff
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
# Get some info frmo the user.
echo " What is the case name? "
read CASE
echo " ";
echo " WHat is the memory file name? :"
read FILE
echo " ";
#
# Create directories if they do not exist
if [ ! -d "$HOME/$CASE/text/strings" ]; then
	mkdir -p $HOME/$CASE/text/strings
fi
#
# Print some text to the screen.
echo " " 
echo " I ma going to take a hash of the memory now."
echo " This can take some time depending on the size of the memory."
echo " It is important for the integrity of the case however."
#
# Start the log file
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo "Today is $(date)" >> $HOME/$CASE/evidence/$CASE.log
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.log
echo "We are going to run strings against the memory file. " >> $HOME/$CASE/evidence/$CASE.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo ""; sleep 1; echo " ";
echo " I will know run strings agains the memory file. "
echo " This can take some time depending on the size of the memroy file. "
echo " "
strings -a $HOME/$CASE/$FILE >> $HOME/$CASE/text/strings/$CASE.strings.txt
strings -a -e l $HOME/$CASE/$FILE >> $HOME/$CASE/text/strings/$CASE.strings.txt
strings -a -e b $HOME/$CASE/$FILE >> $HOME/$CASE/text/strings/$CASE.strings.txt


echo "Today is $(date)" >> $HOME/$CASE/evidence/$CASE.log
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.log
echo "We are going to run strings against the memory file. " >> $HOME/$CASE/evidence/$CASE.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo ""; sleep 1; echo " ";


#
# EOF

