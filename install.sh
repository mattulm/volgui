#/bin/bash
#
# This script is designed to do the basic initial investigation for a memory image.
# By: Matthew Ulm
# Date: June 27, 2015
#
# This script was built using the SIFT workstation 3.0
# It is not really an installation script.
# It will only install needed files for things to work 
# within all of the included scripts.
# 
# You need to run it with root level access.
#
### Set some variables
##########################
USER="/home/sansforensics";
HOME="/cases";
TODAY=$(date +"%Y-%m-%d")
FTIME="$(date)"


#
# TO DO: put in some root level access checking fu here.


#
# For Didier Stevens' scripts.
easy_install poster


#
# EOF
