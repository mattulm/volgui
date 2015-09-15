/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Win32OPCHavex
{
    meta:
        Author      = "BAE Systems"
        Date        = "2014/06/23"
        Description = "Rule for identifying OPC version of HAVEX"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $mzhdr = "MZ"
        $dll = "7CFC52CD3F87.dll"
        $a1 = "Start finging of LAN hosts..." wide
        $a2 = "Finding was fault. Unexpective error" wide
        $a3 = "Was found %i hosts in LAN:" wide
        $a4 = "Hosts was't found." wide
        $a5 = "Start finging of OPC Servers..." wide
        $a6 = "Was found %i OPC Servers." wide
        $a7 = "OPC Servers not found. Programm finished" wide
        $a8 = "%s[%s]!!!EXEPTION %i!!!" wide
        $a9 = "Start finging of OPC Tags..." wide

    condition:
        $mzhdr at 0 and ($dll or (any of ($a*)))
}

rule Win32FertgerHavex
{
    meta:
        Author      = "BAE Systems"
        Date        = "2014/06/23"
        Description = "Rule for identifying Fertger version of HAVEX"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $mz = "MZ"
        $a1="\\\\.\\pipe\\mypipe-f" wide
        $a2="\\\\.\\pipe\\mypipe-h" wide
        $a3="\\qln.dbx" wide
        $a4="*.yls" wide
        $a5="\\*.xmd" wide
        $a6="fertger" wide
        $a7="havex"
    
    condition:
        $mz at 0 and 3 of ($a*) 
}

rule Havex_Trojan_PHP_Server
{
    meta:
        Author      = "Florian Roth"
        Date        = "2014/06/24"
        Description = "Detects the PHP server component of the Havex RAT"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $s1 = "havex--></body></head>"
        $s2 = "ANSWERTAG_START"
        $s3 = "PATH_BLOCKFILE"

    condition:
        all of them
} 

rule Havex 
{
	meta:
	author = "Marcus J Ruffin"
	yaraexchange = "Do Not Distribute"
	date = "2015-01"
	filetype = "PE"
	malwaretype = "Havex" 
	reference = "VirusTotal"
		
	strings:
	 
     	$mz = "MZ"
	$str1 = "Copyright (c) J.S.A.Kapp 94-96"
      	$str2 = "cmd.exe /c"
      	$str3 = "rwalton" 
			
	condition:
	
	$mz at 0 and 2 of ($str1,$str2,$str3)
      }

	  
rule Havex_Trojan_PHP_Server
	{
	meta:
		description = "Detects the PHP server component of the Havex RAT"
		date = "2014-06-24"
		author = "Florian Roth"
		reference = "http://goo.gl/GO5mB1"
	strings:
	    $s1 = "havex--></body></head>"
		$s2 = "ANSWERTAG_START"
		$s3 = "PATH_BLOCKFILE"
	condition:
	    all of them
}

rule Havex_Trojan
	{
	meta:
		description = "Detects the Havex RAT malware"
		date = "2014-06-24"
		author = "Florian Roth"
		reference = "http://goo.gl/GO5mB1"
		hash = "7933809aecb1a9d2110a6fd8a18009f2d9c58b3c7dbda770251096d4fcc18849"
	strings:
		$magic = { 4d 5a }	
	
	    $s1 = "Start finging of LAN hosts..." fullword wide
		$s2 = "Finding was fault. Unexpective error" fullword wide
		$s3 = "Hosts was't found." fullword wide
		$s4 = "%s[%s]!!!EXEPTION %i!!!" fullword wide
		$s5 = "%s  <%s> (Type=%i, Access=%i, ID='%s')" fullword wide
		$s6 = "Was found %i hosts in LAN:" fullword wide
		
		$x1 = "MB Connect Line GmbH" wide fullword
		$x2 = "mbCHECK" wide fullword
	condition:
	    $magic at 0 and ( 2 of ($s*) or all of ($x*) )
}

