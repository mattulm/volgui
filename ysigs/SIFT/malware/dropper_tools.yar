rule psexec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "Sysinternals PsExec Generic"
	filetype = "EXE"
	version = "0.2"
	date = "1/30/2014"
strings:
	$s1 = "PsInfSvc"
	$s2 = "%s -install"
	$s3 = "%s -remove"
	$s4 = "psexec" nocase
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule monitor_tool_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Monitoring Tool??"
strings:
	$s1 = "RCPT TO"
	$s2 = "MAIL FROM"
	$s3 = "AUTH LOGIN"
	$s4 = "Reply-To"
	$s5 = "X-Mailer"
	$s6 = "crypto"
	$s7 = "test335.txt" wide
	$s8 = "/c del"
condition:
	uint16(0) == 0x5A4D and 7 of ($s*)
}

rule blazingtools
{
meta:
	author = "@patrickrolsen"
	reference = "Blazing Tools - http://www.blazingtools.com (Keyloggers)"
strings:
	$s1 = "blazingtools.com"
	$s2 = "Keystrokes" wide
	$s3 = "Screenshots" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule keyfinder_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Magical Jelly Bean KeyFinder"
strings:
	$s1 = "chgxp.vbs"
	$s2 = "officekey.exe"
	$s3 = "findkey.exe"
	$s4 = "xpkey.exe"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}

rule pstgdump
{
meta:
	author = "@patrickrolsen"
	reference = "pstgdump"
strings:
	$s1 = "fgdump\\pstgdump"
	$s2 = "pstgdump"
	$s3 = "Outlook"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule dump_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Related to pwdump6 and fgdump tools"
strings:
	$s1 = "lsremora"
	$s2 = "servpw"
	$s3 = "failed: %d"
	$s4 = "fgdump"
	$s5 = "fgexec"
	$s6 = "fgexecpipe"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule cmd_shell
{
meta:
	author = "@patrickrolsen"
	reference = "Windows CMD Shell"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "cmd.pdb"
	$s2 = "CMD Internal Error %s"
condition:
	uint16(0) == 0x5A4D and (all of ($s*)) and filesize <= 380KB
}

rule procdump
{
meta:
	author = "@patrickrolsen"
	reference = "Procdump"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "\\Procdump\\"
	$s2 = "procdump"
	$s3 = "Process"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule nbtscan
{
meta:
	author = "@patrickrolsen"
	reference = "nbtscan"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "nbtscan" nocase
	$s2 = "subnet /%d"
	$s3 = "invalid target"
	$s4 = "usage: %s"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule winrar_4xx
{
meta:
	author = "@patrickrolsen"
	reference = "WinRar 4.11 CMD line version"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "\\WinRAR\\rar\\"
	$s2 = "WinRAR"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule unknown_creds_dump
{
meta:
	author = "@patrickrolsen"
	reference = "Misc. Creds Dump"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "OpenProcessToken:%d"
	$s2 = "LookupPrivilegeValue:%d"
	$s3 = "AdjustTokenPrivilege:%d"
	$s4 = "\\GetPassword\\"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule scanline_mcafee
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.mcafee.com/us/downloads/free-tools/scanline.aspx"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "CPports.txt"
	$s2 = "ICMP Time"
	$s3 = "Foundsto"
	$s4 = "USER"
	$s5 = {55 50 58 ??} // UPX?
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule windows_credentials_editor
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.ampliasecurity.com/research/wce12_uba_ampliasecurity_eng.pdf"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "NTLMCredentials"
	$s2 = "%d kerberos"
	$s3 = "WCE" nocase
	$s4 = "LSASS.EXE" nocase
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule seven_zip_cmdversion
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.7-zip.org/download.html"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "7za"
	$s2 = "7-Zip"
	$s3 = "Usage:"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule blat_email_301
{
meta:
	author = "@patrickrolsen"
strings:
	$s1 = {33 00 2E 00 30 00 2E 00 31} // 301 uni
	$s2 = "Mar  7 2012"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule gsec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "GSec Dump"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$s1 = "gsecdump"
	$s2 = "usage: gsecdump"
	$s3 = "dump hashes from SAM//AD"
	$s4 = "dump lsa secrets"
	$s5 = "dump_"
	$s6 = "dump all secrets"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule bcp_sql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "iSIGHTPartners_ThreatScape_AA_KAPTOXA PDF - 3f00dd56b1dc9d9910a554023e868dac"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "BCP" nocase
	$s2 = "SQLState = %s"
	$s3 = "Warning = %s"
	$s5 = ";database="
	$s6 = "FIRE_TRIGGERS"

condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule osql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "O/I SQL - SQL query tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "osql\\src"
	$s2 = "OSQLUSER"
	$s3 = "OSQLPASSWORD"
	$s4 = "OSQLSERVER"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule port_forward_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Port Forwarding Tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "%d.%d.%d.%d"
	$s2 = "%i.%i.%i.%i on port %i"
	$s3 = "connect to %s:%i"
	$s4 = "%s:%i established"
	$s5 = "%s:%i closed"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}







/*
The packer rules I got from these sources:
https://malwarecookbook.googlecode.com/svn-history/r5/trunk/3/4/packer.yara
https://code.google.com/p/malware-lu/source/browse/tools/yara/packer.yara
https://github.com/endgameinc/binarypig/blob/master/yara_rules/userdb_panda.yara
https://raw.github.com/endgameinc/binarypig/master/yara_rules/packer.yara
*/

rule _Armadillo_v171
{
meta:
	description = "Armadillo v1.71"
strings:
	$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1}
condition:
	$0 at entrypoint
}

rule _UPX_V200V290
{
meta:
	description = "UPX V2.00-V2.90 -> Markus Oberhumer & Laszlo Molnar & John Reiser"
strings:
	$0 = {FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9}
condition:
	$0
}

rule _UPX_v0896
{
meta:
	description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL"
strings:
	$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF}
condition:
	$0 at entrypoint
}

rule _UPX_290_LZMA
{
meta:
	description = "UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser"
strings:
	$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
	$1 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90}
condition:
	$0 at entrypoint or $1 at entrypoint
}

rule _UPX_Protector_v10x_2
{
meta:
	description = "UPX Protector v1.0x (2)"
strings:
	$0 = {EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB}
condition:
	$0
}

rule _Armadillo_v1xx__v2xx
{
meta:
	description = "Armadillo v1.xx - v2.xx"
strings:
	$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6}
condition:
	$0 at entrypoint
}

rule mpress_2_xx_x86 : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="19/03/2013"
	last_edit="24/03/2013"
	description="MPRESS v2.XX x86  - no .NET"

strings:
	$signature1={60 E8 00 00 00 00 58 05 5A 0B 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6 2B C0 AC 8B C8 80 E1 F0 24} 
condition:
	$signature1 at entrypoint
}

rule mpress_2_xx_x64 : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="19/03/2013"
	last_edit="24/03/2013"
	description="MPRESS v2.XX x64  - no .NET"

strings:
	$signature1={57 56 53 51 52 41 50 48 8D 05 DE 0A 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31} 
condition:
	$signature1 at entrypoint
}

rule mpress_2_xx_net : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="24/03/2013"
	description="MPRESS v2.XX .NET"
strings:
	$signature1={21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}
condition:
	$signature1
}