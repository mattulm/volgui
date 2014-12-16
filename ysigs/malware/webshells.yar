rule GIF_exploit
{
meta:
	author = "@patrickrolsen"
	maltype = "GIF Exploits"
	version = "0.1"
	reference = "code.google.com/p/caffsec-malware-analysis"
	date = "2013-12-14"
strings:
	$magic = {47 49 46 38 ?? 61} // GIF8<version>a
	$s1 = "; // md5 Login" nocase
	$s2 = "; // md5 Password" nocase
	$s3 = "shell_exec"
	$s4 = "(base64_decode"
	$s5 = "<?php"
	$s6 = "(str_rot13"
	$s7 = ".exe"
	$s8 = ".dll"
condition:
	($magic at 0) and any of ($s*)
}

rule html_exploit_GIF
{
meta:
	author = "@patrickrolsen"
	maltype = "Web Shells"
	version = "0.1"
	reference = "code.google.com/p/caffsec-malware-analysis"
	date = "2013-12-14"
strings:
	$magic = {47 49 46 38 ?? 61} // GIF8<version>a
	$s1 = {3c 68 74 6d 6c 3e} // <html>
	$s2 = {3c 48 54 4d 4c 3e} // <HTML>
condition:
	($magic at 0) and (any of ($s*))
}

rule web_shell_crews
{
meta:
	author = "@patrickrolsen"
	maltype = "Web Shell Crews"
	version = "0.5"
	reference = "http://www.exploit-db.com/exploits/24905/"
	date = "02/26/2014"
strings:
	$s1 = "v0pCr3w"
	$s2 = "BENJOLSHELL"
	$s3 = "EgY_SpIdEr"
	$s4 = "<title>HcJ"
	$s5 = "0wn3d"
	$s6 = "OnLy FoR QbH"
	$s7 = "wSiLm"
	$s8 = "b374k r3c0d3d"
	$s9 = "x'1n73ct|d"
	$s10 = "## CREATED BY KATE ##"
	$s11 = "Ikram Ali"
	$s12 = "FeeLCoMz"
	$s13 = "s3n4t00r"
	$s14 = "FaTaLisTiCz_Fx"
	$s15 = "feelscanz.pl"
	$s16 = "##[ KONFIGURASI"
	$s17 = "Created by Kiss_Me"
	$s18 = "Casper_Cell"
	$s19 = "# [ CREWET ] #"
	$s20 = "BY MACKER"
	$s21 = "FraNGky"
	$s22 = "1dt.w0lf"
	$s23 = "Modification By iFX"
	$s24 = "Dumped by C99madShell.SQL"
	$s25 = "Hacked By Alaa"
	$s26 = "XXx_Death_xXX"
	$s27 = "zehir3"
	$s28 = "zehirhacker"
	$s29 = "Shell Tcrew"
	$s30 = "w4ck1ng"
	$s31 = "TriCkz"
	$s32 = "TambukCrew"
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}

rule misc_php_exploits
{
meta:
	author = "@patrickrolsen"
	version = "0.4"
	data = "12/29/2013"
	reference = "Virus Total Downloading PHP files and reviewing them..."
strings:
	$php = "<?php"
	$s1 = "eval(gzinflate(str_rot13(base64_decode("
	$s2 = "eval(base64_decode("
	$s3 = "eval(gzinflate(base64_decode("
	$s4 = "cmd.exe /c"
	$s5 = "eva1"
	$s6 = "urldecode(stripslashes("
	$s7 = "preg_replace(\"/.*/e\",\"\\x"
	$s8 = "<?php echo \"<script>"
	$s9 = "'o'.'w'.'s'" // 'Wi'.'nd'.'o'.'w'.'s'
	$s10 = "preg_replace(\"/.*/\".'e',chr"
	$s11 = "exp1ode"
	$s12 = "cmdexec(\"killall ping;"
	$s13 = "ms-mx.ru"
	$s14 = "N3tsh_"
condition:
	not uint16(0) == 0x5A4D and $php and any of ($s*)
}

rule zend_framework
{
meta:
	author = "@patrickrolsen"
	maltype = "Zend Framework"
	version = "0.3"
	date = "12/29/2013"
strings:
	$php = "<?php"
	$s = "$zend_framework" nocase
condition:
	not uint16(0) == 0x5A4D and $php and $s
}

rule jpg_web_shell
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "12/19/2013"
	reference = "http://www.securelist.com/en/blog/208214192/Malware_in_metadata"
strings:
	$magic = { ff d8 ff e? } // e0, e1, e8
	$s1 = "<script src"
	$s2 = "/.*/e"
	$s3 = "base64_decode"
condition:
	($magic at 0) and 1 of ($s*)
}  

rule php_misc_shells
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "01/30/2014"
	reference = "N/A"
strings:
	$php = "<?php"
	$s1 = "second stage dropper"
	$s2 = "SO dumped "
	$s3 = "killall -9 "
	$s4 = "1.sh"
	$s5 = "faim.php"
	$s6 = "file_get_contents("
	$s7 = "$auth_pass ="
	$s8 = "eval($" // Possible FPs
	$s9 = "Find *config*.php"
	$s10 = "Show running services"
	$s11 = "Show computers"
	$s12 = "Show active connections"
	$s13 = "ARP Table"
	$s14 = "Last Directory"
	$s15 = ".htpasswd files"
	$s16 = "suid files"
	$s17 = "writable folders"
	$s18 = "config* files"
	$s19 = "show opened ports"
	$s20 = ".pwd files"
	$s21 = "locate config."
	$s22 = "history files"
	$s23 = "<?php @eval($_POST['cmd']);?>"
	$s24 = "securityprobe.net"
	$s25 = "ccteam.ru"
	$s26 = "c99sh_sources"
	$s27 = "c99mad"
	$s28 = "31373"
	$s29 = "c99_sess_put"
	$s30 = "(\"fs_move_"
	$s31 = "c99sh_bindport_"
	$s32 = "mysql_dump"
	$s33 = "Dumped by c100.SQL"
condition:
	not uint16(0) == 0x5A4D and $php and any of ($s*)
}

rule shell_names
{
meta:
	author = "@patrickrolsen"
	version = "0.2"
	data = "02/01/2014"
	reference = "N/A"
strings:
	$s1 = "faim.php"
	$s2 = "css5.php"
	$s3 = "groanea.php"
	$s4 = "siler.php"
	$s5 = "w.php" fullword
	$s6 = "atom-conf.php"
	$s7 = "405.php"
	$s8 = "pack2.php"
	$s9 = "r57shell.php"
	$s10 = "shell.php" fullword
	$s11 = "dra.php"
	$s12 = "lol.php"
	$s13 = "php-backdoor.php"
	$s14 = "aspxspy.aspx"
	$s15 = "c99.php"
	$s16 = "c99shell.php"
	$s17 = "fx29sh.php"
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}
