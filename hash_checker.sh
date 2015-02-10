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
### Get some information from the user.
#######################################
#
# Get the case name.
echo "I need to get some information first... "
echo "What is the case name? :"
read CASE
if [ ! -d "$HOME/$CASE" ]; then
        echo "It does not look as if the case has been setup just yet.";
        echo "I will create the necessary case directory. Please make sure to";
        echo "Memory file there before proceeding. I will now exit.";
        mkdir -p $HOME/$CASE
        echo " "; sleep 1; exit;
fi


#
#
#
#################################################
#
# It is now time to do some internet things
#################################################









#
# We are going to use a script by Didier Stevens now to check our hashes 
# online. I have slowed down the script a little bit as we are going to 
# compare both the procexedump & procmemexe dumps.
echo "Would you like to run a whois now on the external IPs? (y/n):"
read WHOIS
if [ $WHOIS == "y" ]; then
        mkdir -p $HOME/$CASE/text/ipfiles/whois
        while read i; do
                echo "Checking Whois for..... $i"
                whois $i >> whois/$i.whois.txt
                wget --header="$HEADER" --user-agent="$UA21" "http://who.is/whois-ip/ip-address/$i" -O "whois/$i.whois.html"
                echo " "; sleep 7; echo " "
        done < ipv4connections.external.txt
elif [ $WHOIS == "n" ]; then
        echo "I will not run a whois on these IPs. "
        echo "I will now exit. "
        echo " "
else
        echo "That is un-expected input."
        echo "Exiting ........"
        sleep 1;exit;
fi
cd $HOME/$CASE;



echo "Which set of hashes would you like to check? :";
echo " md5, sha1, or sha256? :";
read UAHASH
echo "Let's check with Virus Total";
echo "Thank you to DIdier Stevens for this portion of the script";
cd $HOME/$CASE/
python $VTSE --key=$APIK -f procexedump/pexe.$UAHASH.F.txt
mv $HOME/virus*.* procexedump;
python $VTSE --key=$APIK -f procmemdump/pmem.$UAHASH.F.txt
mv $HOME/virus*.* procmemdump;
echo " "; sleep 1; echo " ";
#
echo " "
echo "Now going to compare on Total Hash"
while read -r line; do
        wget  --header="$HEADER" --user-agent="$UA22" "http://totalhash.com/search/hash:$line" -O "$HOME/$CASE/procexedump/$THSH/$line.thash.html"
        sleep 7;
done < procmemdump/pexe.$UAHASH.F.txt
echo " "; sleep 1; echo " ";
#
while read -r line; do
        wget  --header="$HEADER" --user-agent="$UA21" "http://totalhash.com/search/hash:$line" -O "$HOME/$CASE/procexedump/$THSH/$line.thash.html"
        sleep 7;
done < procmemdump/pmem.$UAHASH.F.txt
echo " "; sleep 1; echo " ";
#

echo "Now we will chec with VIrus Sign. "
echo "For this we will only check the SHA 256 file. ";
mkdir -p procexedump/virusign; mkdir -p procmemdump/virusign;
while read -r line; do
	wget --header="$HEADER" --user-agent="$UA22" "http://www.virusign.com/details.php?hash=$line" -O "$HOME/$CASE/procexedump/virusign/$line.sha256.thash.html"
        sleep 5;
done < $HOME/$CASE/procexedump/pexe.256.F.txt
echo " "; sleep 1; echo " ";
#
while read -r line; do
        wget --header="$HEADER" --user-agent="$UA22" "http://www.virusign.com/details.php?hash=$line" -O "$HOME/$CASE/procmemdump/virusign/$line.sha256.thash.html"
        sleep 5;
done < $HOME/$CASE/procmemdump/pexe.256.F.txt
echo " "; sleep 1; echo " ";









#
# EOF




