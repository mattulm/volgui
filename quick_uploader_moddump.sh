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

cd $HOME/$CASE/moddump;
if [ ! -f "modlist.txt" ]; then
	for i in *.dll; do
		echo $i >> modlist.txt
	done
fi 
#
#
# Get more info from user
echo "What is your API Key for VT? :"
read APIK
cd $HOME/$CASE/moddump;
python $VTSS -k $APIK -d 18 -f modlist.txt
 

#
# EOF

