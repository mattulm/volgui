'''
PyInstaller Extractor v1.1 (Supports pyinstaller 2.1)
Author : extremecoders
E-mail : extremecoders@mail.com
Date   : 16-Feb-2014
https://sourceforge.net/projects/pyinstallerextractor/

Extracts a pyinstaller generated executable file.
No PyInstaller installation needed!
The Script has it all.

Usage : Just copy this script to the directory where your exe resides
        and run the script with the exe file name as a parameter

C:\Your\Path\To\Exe\>python pyinstxtractor.py <exefilename>

Licensed under GPL.
You are free to modify this source code according to your needs.
'''

import os
import struct
import marshal
import zlib
import sys

try:
    filename=sys.argv[1]
except:
    sys.exit('Error: No filename provided')

try:
    exeFile=open(filename,'rb')
except:
    sys.exit('Error: Cannot open file %s' %(filename))

exeFile.seek(0,os.SEEK_END)         #Navigaate to EOF
end=exeFile.tell()                  #Get EOF Position

COOKIE_SIZE=24
MAGIC='MEI\014\013\012\013\016'

exeFile.seek(end-COOKIE_SIZE,os.SEEK_SET)   #Navigate to COOKIE position

magic = exeFile.read(8)

if magic != MAGIC:
    # Check new pyinstaller format
    exeFile.seek(0, os.SEEK_END)
    COOKIE_SIZE = 24 + 64
    exeFile.seek(end - COOKIE_SIZE, os.SEEK_SET)
    magic = exeFile.read(8)
    if magic != MAGIC:
        sys.exit('Magic mismatch : Not a pyinstaller archive')

# Navigate to COOKIE position
exeFile.seek(end - COOKIE_SIZE, os.SEEK_SET)

if COOKIE_SIZE == 24:
    try:
        (magic,lengthofPackage,TOC,TOClen,pyvers)=struct.unpack('!8siiii',exeFile.read(COOKIE_SIZE)) #Read CArchive cookie
    except:
        sys.exit('Error : Unsupported pyinstaller version or not a pyinstaller archive')

elif COOKIE_SIZE == 24+64:
    try:
        (magic,lengthofPackage,TOC,TOClen,pyvers,pylibname)=struct.unpack('!8siiii64s',exeFile.read(COOKIE_SIZE)) #Read CArchive cookie
    except:
        sys.exit('Error : Unsupported pyinstaller version or not a pyinstaller archive')

if pyvers==27:
    PYC_HEADER='\x03\xF3\x0D\x0A\x00\x00\x00\x00'
elif pyvers==26:
    PYC_HEADER='\xD1\xF2\x0D\x0A\x00\x00\x00\x00'
elif pyvers==25:
    PYC_HEADER='\xB3\xF2\x0D\x0A\x00\x00\x00\x00'
else:
    sys.exit('Error : Unsupported Python version (Only Python 2.5, 2.6, 2.7 are supported')

APPENDED_DATA_POS=end-lengthofPackage   #The data that is appended at the end of the PE file

#Now read CArchive TOC
exeFile.seek(-lengthofPackage,os.SEEK_END)
exeFile.seek(TOC,os.SEEK_CUR)

remaining=TOClen

while remaining>0:
    (thisTOCLen,)=struct.unpack('!i',exeFile.read(4))

    (thisTocPos, compDataSize, uncompDataSize, compFlag, typeCompData, name)= \
    struct.unpack('!iiiBc%ds' %(thisTOCLen-18),exeFile.read(thisTOCLen-4)) #4 bytes already read in previous step

    #Save current file ptr
    savedPtr=exeFile.tell()

    #Navigate to this data
    exeFile.seek(APPENDED_DATA_POS+thisTocPos)

    #Now read the data
    buf=exeFile.read(compDataSize)

    #Now decompress the data if it is compressed
    if compFlag==1:
        buf=zlib.decompress(buf)

    #Remove trailing null bytes from name
    name=name.rstrip('\00')

    bpath=os.path.dirname(name)
    if bpath!='':
        #Check if path exists, create if not
        if os.path.exists(bpath)==False:
            os.makedirs(bpath)
    fd=open(name,'wb')
    fd.write(buf)
    fd.close()

    #Now if the file is a pyz extract its contents
    if typeCompData=='z':
        #Create a directory having same name as that of the pyz with _extracted appended
        dirName=name+'_extracted'
        if os.path.exists(dirName)==False:
            os.mkdir(dirName)
        archive=open(name,'rb') #Open the pyz file
        archive.seek(8)           #Skip 8 bytes (MAGIC)
        (offset,)=struct.unpack("!i",archive.read(4))
        archive.seek(offset)
        toc=marshal.load(archive)

        for key in toc.keys():
            (ispkg, pos, length)=toc.get(key)
            archive.seek(pos)
            compressedobj=archive.read(length)
            decomp=zlib.decompress(compressedobj)
            pycFile=open(os.path.join(dirName,key+".pyc"),'wb')
            #Pyinstaller always removes the pyc file header, we have to add it to make the pyc file valid
            pycFile.write(PYC_HEADER)
            pycFile.write(decomp)
            pycFile.close()

        archive.close()

    #Now go to saved file ptr
    exeFile.seek(savedPtr)
    remaining=remaining-thisTOCLen

exeFile.close()
print 'Successfully extracted Pyinstaller archive : %s' %(filename)
print
print 'Now use Easy Python Decompiler v1.1 to decompile the pyc files'
print 'Choose Uncompyle2 as the decompiler engine as the other engine'
print 'is unstable and can crash although it is very fast.'
