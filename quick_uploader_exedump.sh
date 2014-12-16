#!/bin/bash
#
# Set up some global variables
VOL="vol.py"
HOME="/cases"
VTSS="/home/sansforensics/volgui/tools/dsvtsubmit.py"
#
# Need to read in the config file here
# For now we will statically

#
# Get info from the user
# Get the case name from the user
echo "What is the case name? :"
read CASE
#

cd $HOME/$CASE/procexedump;
if [ ! -f "pexelist.txt" ]; then
	for i in *.exe; do
		echo $i >> pexelist.txt
	done
fi 
#
#
# Get more info from user
echo "What is your API Key for VT? :"
read APIK
cd $HOME/$CASE/procexedump;
python $VTSS -k $APIK -d 18 -f pexelist.txt
 

#
# EOF

