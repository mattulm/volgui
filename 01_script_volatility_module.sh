#
### Start with some basic text files and scans of the memory
### Grab network first so we can start working on that seperatly.
###################################################################
cd $HOME/$CASE/text; mkdir -p $HOME/$CASE/text/ipfiles;
echo "At this time, this script can only perform the netscan operation on a few profiles"
echo "I will add other profiles at a later time as is needed. "
echo " ";
if [ ! -f "$HOME/$CASE/text/netscan.txt" ]; then
	if [ $PRFL = "Win7SP0x86" ]; then
        	echo "I will know grab the network information.  "
        	$VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
	elif [ $PRFL = "Win7SP1x86" ]; then
		echo "I will know grab the network information.  "
                $VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
	elif [ $PRFL = "Win7SP0x64" ]; then
		echo "I will know grab the network information.  "
                $VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
	elif [ $PRFL = "Win7SP1x64" ]; then
		echo "I will know grab the network information.  "
                $VOL -f $HOME/$CASE/$FILE --profile=$PRFL netscan > netscan.txt
       	else
        	echo "It looks as if the netscan module has already been run."
                echo "I am skipping this step for now. "
                sleep 1; echo " ";
        fi
else
        echo "This script can not scan network connections yet for the selected profile"
        echo "Please use the appropriate memory profile script to parse the network date"
fi
echo ""; echo "------------"; echo "";
#
# Let's do some IPv4 parsing. (for now)
if [ -f "$HOME/$CASE/text/netscan.txt" ]; then
	echo "Let's strip out some information from the netscan file now."
	cat netscan.txt | grep -E -o '(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-5][0-9]|[01]?[0-9][0-9]?)' | sort | uniq > ipfiles/ipv4.txt
	cd $HOME/$CASE/text/ipfiles;
	cat ipv4.txt | egrep -v '(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)' | sort | uniq > ipv4.ext.txt;
	echo "This is the number of unique external addresses from the netscan file. "
	wc -l ipv4.ext.txt;
	echo "Number of unique external addresses from the netscan file. " >> $HOME/$CASE/evidence/$CASE.log
	wc -l ipv4.ext.txt >> $HOME/$CASE/evidence/$CASE.log
	echo " ";
fi
#
# Let's search online for our external IPs
if [ -f "$home/$CASE/text/ipfiles/ipv4.ext.txt"]; then
	while read x; do
		wget --header="$HEADER" --user-agent="$UA20" "https://www.virustotal.com/en/ip-address/$x/information/" -O "vt.$x.html"
		sleep 3;
	done < ipv4.ext.txt
fi
#
#
# Let's do our process scans to get started on our analysis
##############################################################
cd $HOME/$CASE
process=( pslist psxview )
for i in "${process[@]}"; do
	if [ ! -f "text/$i.txt" ]; then
		echo "$i module has been run at $(date), against the memory file."
                echo "$i module has been run at $(date), against the memory file." >> $HOME/$CASE/evidence/$CASE.log
		$VOL -f $FILE --profile=$PRFL $i > text/$i.txt
		echo " "; sleep 1; echo "";
	else 
		echo "It looks as if the $i module has already been run."
		echo "I am skipping this step for now. "
		sleep 1; echo " ";
	fi
done
echo " Done with our array of modules"
#
# Looking for svchost with this section.
cd $HOME/$CASE/text;
cat pslist.txt | grep 0x | grep svchost | awk '{ print $3 }' > svchost.pids.list
cat pslist.txt | grep 0x | grep svchost | awk '{ print $4 }' > svchost.parent.list
cat pslist.txt | grep -v DagentConfig | grep -v dagentui | grep -v "net.exe" > pslist.noaltiris.txt
#
#
SVCHC=($(wc -l svchost.pids.list))
echo "There are $SVCHC svchost processes discovered within RAM."
echo "There are $SVCHC svchost processes discovered within RAM." >> $HOME/$CASE/evidence/$CASE.log
echo " " >> $HOME/$CASE/evidence/$CASE.log; echo " ";
cat svchost.parent.list | sort | uniq > svchost.parent
SVCPC=($(wc -l svchost.parent))
echo "There ( is - are ) $SVCPC unique svchost parent processes"
echo "There ( is - are ) $SVCPC unique svchost parent processes" >> $HOME/$CASE/evidence/$CASE.log
echo " " >> $HOME/$CASE/evidence/$CASE.log; echo " ";
echo "Here are all of the svchost PIDs "; echo " ";
cat svchost.pids.list; echo " ";
echo "Here are all of the svchost PIDSs " >> $HOME/$CASE/evidence/$CASE.log
cat svchost.pids.list >> $HOME/$CASE/evidence/$CASE.log
echo " " >> $HOME/$CASE/evidence/$CASE.log
echo " " >> $HOME/$CASE/evidence/$CASE.log
#
#
# Trying to pull the memory offsets from a few of the process lists.
# THe thought is to pull these, and use them to pull the executables seperately.
# from teh PID file, as a means to check for process hallowing.
cat $HOME/$CASE/text/pslist.txt | grep 0x | cut -c-10 >> $HOME/$CASE/procexedump/memory-offsets-working.txt
cat $HOME/$CASE/procexedump/memory-offsets-working.txt | sort | uniq > $HOME/$CASE/procexedump/memory-offsets.txt;
#
# 
echo "I am going to run the procexedump command now."; echo " "; echo " ";
$VOL -f $HOME/$CASE/$FILE --profile=$PRFL procexedump -u --dump-dir $HOME/$CASE/procexedump;
ls $HOME/$CASE/procexedump/*.exe >> $HOME/$CASE/procexedump/pexe.files.list
#
# Adobe Malware Classifier
echo "I am going to run the file command, and use the "
echo "Adobe Malware Scanner against each file dumped. "
cd $HOME/$CASE/procexedump;
rm -rf pexe.md5.list;
for i in *.exe; do
	echo "-------------------------" >> exeresults.txt;
	file $i >> exeresults.txt;
	md5sum $i >> exeresults.txt;
	/usr/local/bin/pescan $i >> exeresults.txt;
	echo " " >> exeresults.txt;
	echo "Adobe Malware CLassifier....." >> exeresults.txt;
	python $ADMC -f $i -n 1 >> exeresults.txt;
	python $ADMC -f $i -n 2 >> exeresults.txt;
	python $ADMC -f $i -n 3 >> exeresults.txt;
	python $ADMC -f $i -n 4 >> exeresults.txt;
	echo " " >> exeresults;
	echo " " >> exeresults;
	md5sum $i >> pexe.md5.list;
done
#
# Clean up the MD5 file for searching later.
cat pexe.md5.list | cut -c 1-32 | sort | uniq >> pexe.md5;
#
# Didier Stevens VT Submit script.
ls *.exe >> pexe.list
python $DSUB -k $APIK -f pexe.list
#
#
mkdir svchost;
while read p; do
	cp executable.$p.exe svchost
done < $HOME/$CASE/text/svchost.pids.list
cd svchost; echo " "; echo " ";
echo "Use ssdeep against the svchost processes. " >> $HOME/$CASE/evidence/$CASE.svchost.log
echo " " >> $HOME/$CASE/evidence/$CASE.svchost.log
ssdeep -b -a -p *.exe >> $HOME/$CASE/evidence/$CASE.svchost.log
echo "Now I will use ssdeep against the svchost processes. ";
echo " "; echo " ";
ssdeep -b -a -p *.exe
cd $HOME/$CASE
#
# Running the malfind plugin
cd $HOME/$CASE;
$VOL -f $FILE --profile=$PRFL malfind --dump-dir malfind >> $HOME/$CASE/malfind/malfind.txt
echo "Done runing the malfind plugin. "
echo "I will now go through those results a little bit. "
cd $HOME/$CASE/malfind;
cat malfind.txt | grep -B4 MZ | grep "Pid:" | cut -f 3 -d":" | cut -f 2 -d" " >> malfind.pids.list
file *.dmp | grep PE32 | cut -f 1 -d":" | wc -l >> malfind.pe32.count
file *.dmp | grep PE32 | cut -f 1 -d":" >> malfind.pe32.list
echo " "; echo " ";
#
# Going through the malfind files now
# Some PE file tools, and strings.
LINE=$(head -n 1 malfind.pe32.list)
if [ $LINE -eq 0 ]; then
	echo "According to malfind, there are no injected processes identified, with the "
	echo "malfind plugin. We will skip a few steps, and dig right into our modules "
	echo "section. "
	echo " ";
else
	echo "I am going to use a few tools against the files. This could take some time. "
	while read w; do
		file $w >> $HOME/$CASE/malfind.petools.txt
		md5sum $w >> $HOME/$CASE/$i.petools.txt
		#/usr/local/bin/pescan $w >> $HOME/$CASE/$i.petools.txt
		echo " " >> $HOME/$CASE/$i.petools.txt
		python $ADMC -f $w >> $HOME/$CASE/$i.petools.txt
	done < malfind.pe32.list
fi
#
# Grab the strings from any injected executable according to malfind.

if [ $LINE -eq 0 ]; then
	echo "Skipping a few more tools. "
else 
	cd $HOME/$CASE/procexedump;
	echo "I am going to run strings against all of the injected executables "
	echo "identified by the malfind plugin run earlier. "
	echo " "
	while read p; do
		strings -a -e l executable.$p.exe >> $HOME/$CASE/malfind/executable.$p.strings;
		echo " " >> $HOME/$CASE/malfind/executable.$p.strings; echo " " >> $HOME/$CASE/malfind/executable.$p.strings;
		echo "-----------------------------------------------" >> $HOME/$CASE/malfind/executable.$p.strings;
		strings -a -e b executable.$p.exe >> >> $HOME/$CASE/malfind/executable.$p.strings;
	        echo " " >> $HOME/$CASE/malfind/executable.$p.strings; echo " " >> $HOME/$CASE/malfind/executable.$p.strings;
	        echo "-----------------------------------------------" >> $HOME/$CASE/malfind/executable.$p.strings;
		strings -a executable.$p.exe >> >> $HOME/$CASE/malfind/executable.$p.strings;
	done < $HOME/$CASE/malfind/malfind.pids.list
	echo " "; echo "-----"; echo " ";
	#
	# Some file tools now
	echo "I am going to use some tools against the injected executables "
	echo "THis could take a little while. "
	while read r; do
		echo "---------------------------------" >> $HOME/$CASE/malfind/executable.$r.log
		file executable.$r.exe >> $HOME/$CASE/malfind/executable.$r.log
		md5sum executable.$r.exe >> $HOME/$CASE/malfind/executable.$r.log
		#/usr/local/bin/pescan executable.$r.exe >> $HOME/$CASE/malfind/executable.$r.log
		echo " " >> $HOME/$CASE/malfind/executable.$r.log
		python $ADMC -f executable.$r.exe >> $HOME/$CASE/malfind/executable.$r.log
	done < $HOME/$CASE/malfind/malfind.pids.list
fi
#
# Dump the VAD for the injected files as well
cd $HOME/$CASE
while read t; do
	vol.py -f $FILE --profile=$PRFL vaddump --dump-dir vaddump -p $t >> vaddump/vaddump.$t.txt
done < $HOME/$CASE/malfind/malfind.pids.list
echo " "; echo "-----"; echo " ";
#
#
# Now some moddump stuff
##########################################
echo "I am going to run the moddump command now.";
cd $HOME/$CASE;
$VOL -f $HOME/$CASE/$FILE --profile=$PRFL moddump --dump-dir $HOME/$CASE/moddump >> $HOME/$CASE/moddump/moddump.txt
cd $HOME/$CASE/moddump;
ls *.sys >> moddump.list
md5sum *.sys >> mod.md5.list
# 
# Search on Virus Total
cat mod.md5.list | cut -c 1-32 | sort | uniq >> mod.md5;
$DSVT -k $APIK -f mod.md5
#
#
#########
########################################################
#
# Run a last series of scans against the memory file.
##################################################################
cd $HOME/$CASE/
modscans=( ssdt cmdscan consoles shellbags dlllist envars )
for i in "${modscans[@]}"; do
        if [ ! -f "text/$i.txt" ]; then
                echo "$i module will be run at $(date), against the memory file."
                echo "$i module will be run at $(date), against the memory file." >> $HOME/$CASE/evidence/$CASE.log
                $VOL -f $FILE --profile=$PRFL $i > text/$i.txt
                echo " "; sleep 1; echo "";
        else
                echo "It looks as if the $i module has already been run."
                echo " "; sleep 1; echo " ";
        fi
done
echo " ";
#
# Going to look through the SSDT file now
cd $HOME/$CASE/text;
cat ssdt.txt | egrep -iv '(ntoskrnl|win32k)' >> ssdt.nonwindows.txt
cat ssdt.txt | egrep -iv '(ntoskrnl|win32k|unknown)' >> ssdt.investigate.txt
#
# Going to go through the dlllist file for a bit
cd $HOME/$CASE/text;
cat dlllist.txt | grep -iv system32 >> dlllist.nosystem32.txt
cat dlllist.txt | grep -i system32 >> dlllist.system32.txt
cat dlllist.txt | grep -B2 -i "Command line" >> dlllist.cmdline.txt
echo "I am going to pull out some of the well known Windows DLLs. "  >> dlllist.system32.nowin.txt
# First round couple rounds....
cat dlllist.system32.txt | grep -iv "kerberos.DLL" | grep -iv "cryptdll.dll" | grep -iv "kernel32.dll" | grep -iv "ntdll.dll" | grep -iv "USER32.dll" >> dllsys32.1.txt
cat dllsys32.1.txt | grep -iv "GDI32.dll" | grep -iv "ole32.dll" | grep -iv "ADVAPI32.dll" | grep -iv "WS2_32.dll" | grep -iv "CRYPTBASE.dll" >> dllsys32.2.txt
cat dllsys32.2.txt | grep -iv "d3d9.dll" | grep -iv "KERNELBASE.dll" | grep -iv "OLEAUT32.dll" | grep -iv "mswsock.dll" | grep -iv "CRYPT32.dll" >> dllsys32.3.txt
cat dllsys32.3.txt | grep -iv "SHELL32.dll" | grep -iv "tcpmon.dll" | grep -iv "usbmon.dll" | grep -iv "SYSFER.DLL" | grep -iv "msvcrt.dll" >> dllsys32.4.txt
cat dllsys32.4.txt | grep -iv "umrdp.dll" | grep -iv "upnp.dll" | grep -iv "apphelp.dll" | grep -iv "HID.DLL" | grep -iv "taskschd.dll" >> dllsys32.5.txt
cet dllsys32.5.txt | grep -iv "es.dll" | grep "RPCRT4.dll" >> dlllist.system32.nowin.txt


#
# I want to play with the envars file now a little bit.
cd $HOME/$CASE/text;
cat envars.txt | grep -iv user >> envars.user.txt
cat envars.txt | grep -iv system >> envars.system.txt
#
#
# Some optional plugins. we will ask the user to see if they want to
# run these or not.
####################################################################
optional=( userassist mbrparser mftparser filescan modscan  )















#
#
# Let's search online for the stuff we uplaoded
####################################################################
#
# Virus Total - procexedump files first
cd $HOME/$CASE/procexedump;
python $DSVT -k $APIK -f pexe.md5;
tr ';' ', ' < virustotal-search-20*.csv > virustotal-search-procexedump.csv
#
# Virus Total - moddump files
cd $HOME/$CASE/moddump;
python $DSVT -k $APIK -f mod.md5;
tr ';' ', ' < virustotal-search-20*.csv > virustotal-search-moddump.csv






#
# EOF




