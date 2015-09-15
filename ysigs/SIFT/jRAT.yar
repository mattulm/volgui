/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule jRAT_conf : rat 
{
	meta:
		description = "jRAT configuration" 
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-10-11"
		filetype = "memory"
		version = "1.0" 
		ref1 = "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py" 
		ref2 = "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html" 

	strings:
		$a = /port=[0-9]{1,5}SPLIT/ 

	condition: 
		$a
}


rule jRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/jRat"
		maltype = "Remote Access Trojan"
		filetype = "Java"

    strings:
        $meta = "META-INF"
        $key = "key.dat"
        $conf = "config.dat"
 		$jra1 = "enc.dat"
		$jra2 = "a.class"
		$jra3 = "b.class"
		$jra4 = "c.class"
        $reClass1 = /[a-z]\.class/
        $reClass2 = /[a-z][a-f]\.class/

    condition:
       ($meta and $key and $conf and #reClass1 > 10 and #reClass2 > 10) or ($meta and $key and all of ($jra*))
}
