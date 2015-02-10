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
echo "What is your API Key for VT? :"
read APIK
#
#
cd $HOME/$CASE/dlldump/;
#
#
for i in *.dll; do
	md5sum $i >> dll.md5.txt;
        sha1sum $i >> dll.sha1.txt;
        sha256sum $i >> dll.256.txt;
	ssdeep $i >> dll.ssdeep.txt
        echo $i >> dlllist.txt
done
#
#
cat dll.md5.txt | sort | uniq > dll.md5.F.txt;
python $DSVT -k $APIK -f dll.md5.F.txt;
cp virustotal-search-*.csv $HOME/$CASE/evidence/volatility_dlldump.csv;i


