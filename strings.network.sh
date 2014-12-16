#!/bin/bash
#
#
#
#
# Get some information from the user
echo " WHat is the case name? :"
read CASE
echo " "

#
# Check a few things first.
if [ ! -d "$HOME/$CASE/text" ]; then
	echo " You have not set up your case yet "
elif [ ! -d "$HOME/$CASE/text/strings" ]; then
	mkdir -p $HOME/$CASE/text
elif [ ! -d "$HOME/$CASE/text" ]; then
	mkdir -p $HOME/$CASE/text

fi

#
# Find out what they want to 