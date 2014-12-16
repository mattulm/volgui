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
echo " What is the case name? :"
read CASE
echo " "
#
#
# Check a few things first.
if [ ! -d "$HOME/$CASE/text" ]; then
	echo " You have not set up your case yet ";
fi
if [ ! -d "$HOME/$CASE/text/strings" ]; then
	echo " You have not run strings against the memory file yet ";
fi
#
#
# Find out what they want to do with the full strings report.
cd  $HOME/$CASE/text/strings/;
# Generic Search
echo " A Quick Generic Search....."
cat $CASE.strings.txt | egrep -i 'update|\.exe|System32|Windows|ip|%d.|image' >> $CASE.strings.generic.txt
sleep 1;
# Base Services
echo "Base Services Search....."
cat $CASE.strings.txt | egrep -i 'kernel.dll' >> $CASE.strings.kernel.txt
sleep 1;
# Advanced Services - registry, windows services, user accounts, etc... Search
echo "Advanced Services - registry, windows services, user accounts, etc... Search"
cat $CASE.strings.txt | egrep -i 'advapi32.dll' >> $CASE.strings.advapi32.txt
sleep 1;
# Windows Instructions
echo "Windows Instructions Search....."
cat $CASE.strings.txt | egrep -i 'GetLayout | SetLayout| LoadLibrary | GetProcAddress | LdrGetProcAddress | LdrLadDll | CreateProcess' >> $CASE.strings.WinInstructions.txt
sleep 1;
# Graphics Device Interface
echo "Graphics Device Interface";
cat $CASE.strings.txt | egrep -i 'win32k.sys | gdi32.dll' >> $CASE.strings.graphicsdevice.txt
sleep 1;
# User Interface
echo "User Interface Search...."
cat $CASE.strings.txt | egrep -i 'user32.dll | comctl32.dll' >> $CASE.strings.userinterface.txt
sleep 1;
#
#
# Unknown Searches 
# NEed to do mroe research on these.
# Reading one of the Windows INternals Books is probably most appropriate for these.
echo "Going to go through a series of searches. I need to do more research on thes. Granted."
echo "Search 1"
cat $CASE.strings.txt | egrep -i 'VirtualAlloc | CreateRemoteThread | SetWindowsHook' >> $CASE.strings.s1.txt
sleep 1;
#
#echo "Search 2"
cat $CASE.strings.txt | egrep -i 'Page_Execute_ReadWrite' >> $$CASE.strings.s2.txt
sleep 1;
#
#cat $CASE.strings.txt | egrep -i
#cat $CASE.strings.txt | egrep -i
#cat $CASE.strings.txt | egrep -i
#cat $CASE.strings.txt | egrep -i
#cat $CASE.strings.txt | egrep -i
#cat $CASE.strings.txt | egrep -i











#
# EOF
