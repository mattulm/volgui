#/bin/bash
#
#
#

HOME="/home/sansforensics"

# Get the case name from the user
echo "What is the case name? :"
read CASE

# What is the memory file name
echo "What is the memory file name? :"
read FILE
mkdir -p $HOME/$CASE/text
mkdir -p $HOME/$CASE/evidence

# Start the log file
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo "Today is $(date)" >> $HOME/$CASE/evidence/$CASE.log
echo "What is the investigator name? :"
read NAME
echo "Investigator is $NAME" >> $HOME/$CASE/evidence/$CASE.log
echo "host is $(hostname)" >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo "The file being analyzed is: $FILE" >> $HOME/$CASE/evidence/$CASE.log
md5sum $HOME/$CASE/$FILE >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo "------------------------------------------------------------" >> $HOME/$CASE/evidence/$CASE.log
echo ""
echo ""

# Let's figure out what image we are working with
vol.py -f $HOME/$CASE/$FILE imageinfo
# Ask the user what they want to use
echo "What profile do you want to use for these scans? :"
read PRFL

#
# Let's do some process stuff!
cd $HOME/$CASE
process=( pslist psscan pstree psxview dlllist thrdscan threads)
for i in "${process[@]}"
do
	vol.py -f $HOME/$CASE/$FILE $i --profile=$PRFL > text/$i.txt
done

windows=( svcscan eventhooks )
for i in "${windows[@]}"
do
        vol.py -f $HOME/$CASE/$FILE $i --profile=$PRFL > text/$i.txt
done

malware=( apihooks malfind )
for i in "${malware[@]}"
do
        vol.py -f $HOME/$CASE/$FILE $i --profile=$PRFL > text/$i.txt
done



