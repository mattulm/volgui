rule MS12_052
{
        meta:
                author = "Adnan Mohd Shukor"
                author_email = "adnan.shukor @ G!"
                ref = "MS12-052"
                ref_url = "http://seclists.org/bugtraq/2012/Sep/29"
                cve = "CVE-"
                version = "1"
                impact = 4
                hide = false
        strings:
                $ms12052_2 = /\.getElements?By/ nocase
                $ms12052_3 = /\.removeChild\(/ nocase
                $ms12052_4 = /document\..*?= ?null/ nocase
        condition:
                $ms12052_2 and ($ms12052_3 or $ms12052_4)
}
rule html_CVE_2013_1347
{
meta:
        author = "@patrickrolsen"
        reference = "http://blogs.cisco.com/security/watering-hole-attacks-target-energy-sector"
        hashes = "00ca490898740f9b6246e300ef0ee86f and dc681f380698b2e6dca7c49f699799ad"
        date = "02/01/2014"
strings:
        $html = "html" wide ascii
        $s1 = "DOropRAM" wide ascii
        $s2 = "\\u9090\\u9090\\u9090\\u9090" wide ascii
        $s3 = "shellcode" wide ascii
        $s4 = "unicorn" wide ascii
        $s5 = "helloWorld()" wide ascii
        $s6 = "ANIMATECOLOR" wide ascii
        $s7 = "UPXIgLvY" wide ascii
condition:
        $html and 3 of ($s*)
}
rule CVE_2013_0422
{
        meta:
                description = "Java Applet JMX Remote Code Execution"
                cve = "CVE-2013-0422"
                ref = "http://pastebin.com/JVedyrCe"
                author = "adnan.shukor@gmail.com"
                date = "12-Jan-2013"
                version = "1"
                impact = 4
                hide = false
        strings:
                $0422_1 = "com/sun/jmx/mbeanserver/JmxMBeanServer" fullword
                $0422_2 = "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder" fullword
                $0422_3 = "com/sun/jmx/mbeanserver/MBeanInstantiator" fullword
                $0422_4 = "findClass" fullword
                $0422_5 = "publicLookup" fullword
                $class = /sun\.org\.mozilla\.javascript\.internal\.(Context|GeneratedClassLoader)/ fullword
        condition:
                (all of ($0422_*)) or (all of them)
}
rule APT_digitalgloeb_mitrefund
{
meta:
        author = "ThreatConnect Intelligence Research Team - Wes Hurd"
        example = "25E3744175C8FC370EFC265F99602C72"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
strings:
        $D = "D:\\P\\win\\Release\\"
        $d = "digitalgloeb.com" wide ascii nocase
        $H = {3C 00 2F 00 48 00 3E 00 00 00 00 00 3C 00 48 00 3E 00 00 00 0D 00 0A 00 00 00 00 00 29 00 00 00 78 00 2D 00 44 00 6F 00 77 00 6E 00 28}
        $m = "mitrefund.org" wide ascii nocase
        $st = {5C 00 3F 00 3F 00 5C 00 25 00 73 00 5C 00 74 00 61 00 73 00 6B 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65}
        $x = "x-DownOnly(" wide
condition:
        any of them
}

rule CVE_2013_3893
{
                meta:
                                author = "Brian Bartholomew iSIGHT Partners"
                                maltype = "apt"
                                yaraexchange = "No distribution without author's consent"
                                date = "09/20/2013"
                                descrption = "This rule will detect CVE-2013-3893"
                                reference_1 = "http://technet.microsoft.com/en-us/security/advisory/2887505"
                                reference_2 = "http://blogs.technet.com/b/srd/archive/2013/09/17/cve-2013-3893-fix-it-workaround-available.aspx"
                                status = "Tested against the one known live sample we were able to find and it works"

                strings:
                                $String_1 = "onlosecapture" nocase
                                $String_2 = "setCapture" nocase
                                $String_3 = "CollectGarbage" nocase

                condition:
                                all of them
}
rule APT_tibetonline_Payload {

meta:
        author = "ThreatConnect Intelligence Research Team - Wes Hurd"
        example = "26E442AA18FCEA38E4C652D346627238"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."

strings:
        // These first two strings are hex strings, but they are hardcoded in the binary as ASCII text.
        $7e = "7e160a0a0e4451511c1f1d15500c11110a1b0c500a1551"
        $88 = "88e0fcfcf8b2a7a7eae4e7efa6f1e9e0e7e7a6ebe7e5a7d7c2debebfccdac7bdd1bbc2cbc7cddec4c5c9bdc0d0dcc6d2dcbca7fafbfb"
        $MyType = {4D 79 54 79 70 65 00 00 75 63 62 6F 6F 74}
        $ownin = {6F 77 6E 69 6E 00 00 00 73 65 65 64}

condition:
        any of them

}

rule APT_Spindest
{
meta:
        author = "ThreatConnect Intelligence Research Team - Wes Hurd"
        example = "D1E949AE098A2BFA8B933076C26BD95F"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
strings:
        $af = {61 66 21 69 26 64 39}
        $CLoD = "CLorderDoc"
        $CLoV = "CLorderView"
        $F = {46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 68 00 63 00 31 00 20 00 4D 00 46 00 43 00 20 00 41 00 70 00 70 00 6C 00 69 00 63 00 61 00 74 00 69 00 6F 00 6E}
        $i = "/index.html?id=%ld"
        $l = "/%lu.asp"
        $Mcaf = "Mcafee_INFO"
        $Sym = {00 00 00 00 53 79 6D 61 6E 74 65 63 5F 55 49 00}
condition:
        any of them
}
rule APT_64church
{
meta:
        author = "ThreatConnect Intelligence Research Team - Wes Hurd"
        example = "63FC36F736ABDE5C3A5C2C841F60BB80"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."

        strings:
        $ch = "chinamz2008.gicp"
        $em = "emailaccountinfo.com"
        $fr = "freeminzhu89@gmail.com"
        $ta = {74 61 72 2E 66 6D 74 0F 49 6E 73 74 61 6C 6C 0F 4E 65 65 64 44 65 6C 61 79}

condition:
        any of them
}

rule Barkiofork_APT
{

meta:
        author = "ThreatConnect Intelligence Research Team - Wes Hurd"
        example = "6AB333C2BF6809B7BDC37C1484C771C5"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."

        strings:
        $2011 = "/2011/n325423"
        $Current = {43 75 72 72 65 6E 74 20 75 73 65 72 3A 20 27 00 27 0A 00 00 53 79 73 74 65 6D 20 69 6E 66 6F 20 66 6F 72 20 6D 61 63 68 69 6E 65 20 27 00 00 00 30 00 00 00 50 61 73 73 77 6F 72 64 3A 20 25 73 0A 00 00 00 50 4F 50 33 20 50 61 73 73 77 6F 72 64 00 00 00 55 73 65 72 3A 25 73 0A 00 00 00 00 50 4F 50 33 20 55 73 65 72 00 00 00 5C 63 6D 64 2E 65 78 65}
        $Dreate = {00 00 44 72 65 61 74 65 50 69 70 65 00 00}

condition:
        any of them

}

rule APT_20131218B
{
meta:
        author = "ThreatConnect Intelligence Research Team"
        example = "4E22E8BC3034D0DF1E902413C9CFEFC9"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
strings:
        $cmd = "cmd.exe isn't exist Data"
        $Data = "Data$$12%c%sEXOKData"
        $explorer = {65 78 70 6C 6F 72 65 72 10 2E 65 78 65 C1 09 50 00 4F 10 00 53 00 54 81 02 00 49 00 80 45 00 38}
        $Fi = "File can not be open.Data"
        $fu = "fucklittle.pdb"
condition:
        any of them
}
rule Trojan_Derusbi {
    meta:
                Author = "RSA_IR"
                Date     = "4Sept13"
        File     = "derusbi_variants v 1.3"
        MD5      = " c0d4c5b669cc5b51862db37e972d31ec "

        strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ?? 40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}

        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4 A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}

    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8)
}

rule APT_mophecfbr
{
meta:
        author = "ThreatConnect Intelligence Research Team - Wes Hurd"
        example = "C299ECD9383C6FF42548F0EA31F76E84"
        license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
strings:
        $C = "Can 't initiates windows socket!"
condition:
        any of them
}
rule APT1_Revird_svc
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $dll1 = "nwwwks.dll" wide ascii
        $dll2 = "rdisk.dll" wide ascii
        $dll3 = "skeys.dll" wide ascii
        $dll4 = "SvcHost.DLL.log" wide ascii
        $svc1 = "InstallService" wide ascii
        $svc2 = "RundllInstallA" wide ascii
        $svc3 = "RundllUninstallA" wide ascii
        $svc4 = "ServiceMain" wide ascii
        $svc5 = "UninstallService" wide ascii
    condition:
        1 of ($dll*) and 2 of ($svc*)
}

rule APT1_letusgo
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $letus = /letusgo[\w]+v\d\d?\./
    condition:
        $letus
}


rule TROJAN_Notepad {
        meta:
                Author = "RSA_IR"
                Date     = "4Jun13"
                File     = "notepad.exe v 1.1"
                MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
        strings:
                $s1 = "75BAA77C842BE168B0F66C42C7885997"
                $s2 = "B523F63566F407F3834BCC54AAA32524"
        condition:
                $s1 or $s2
}
rule ccrewQAZ
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "!QAZ@WSX" wide ascii

  condition:
    $a
}

rule DownloaderPossibleCCrew
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "%s?%.6u" wide ascii
    $b = "szFileUrl=%s" wide ascii
    $c = "status=%u" wide ascii
    $d = "down file success" wide ascii
        $e = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)" wide ascii

  condition:
    all of them
}

rule APT1_WARP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $err1 = "exception..." wide ascii
        $err2 = "failed..." wide ascii
        $err3 = "opened..." wide ascii
        $exe1 = "cmd.exe" wide ascii
        $exe2 = "ISUN32.EXE" wide ascii
    condition:
        2 of ($err*) and all of ($exe*)
}
rule CCREWBACK1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "postvalue" wide ascii
    $b = "postdata" wide ascii
    $c = "postfile" wide ascii
    $d = "hostname" wide ascii
    $e = "clientkey" wide ascii
    $f = "start Cmd Failure!" wide ascii
    $g = "sleep:" wide ascii
    $h = "downloadcopy:" wide ascii
    $i = "download:" wide ascii
    $j = "geturl:" wide ascii
    $k = "1.234.1.68" wide ascii

  condition:
    4 of ($a,$b,$c,$d,$e) or $f or 3 of ($g,$h,$i,$j) or $k
}

rule GEN_CCREW1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "W!r@o#n$g" wide ascii
    $b = "KerNel32.dll" wide ascii

  condition:
    any of them
}

rule ccrewDownloader2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "3gZFQOBtY3sifNOl" wide ascii
        $b = "docbWUWsc2gRMv9HN7TFnvnKcrWUUFdAEem9DkqRALoD" wide ascii
        $c = "6QVSOZHQPCMc2A8HXdsfuNZcmUnIqWrOIjrjwOeagILnnScxadKEr1H2MZNwSnaJ" wide ascii

  condition:
    any of them
}
rule LONGRUN_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0)" wide ascii
                $s2 = "%s\\%c%c%c%c%c%c%c" wide ascii
                $s3 = "wait:" wide ascii
                $s4 = "Dcryption Error! Invalid Character" wide ascii

        condition:
                all of them
}

rule MANITSME_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Install an Service hosted by SVCHOST." wide ascii
                $s2 = "The Dll file that to be released." wide ascii
                $s3 = "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
                $s4 = "svchost.exe" wide ascii

                $e1 = "Man,it's me" wide ascii
                $e2 = "Oh,shit" wide ascii
                $e3 = "Hallelujah" wide ascii
                $e4 = "nRet == SOCKET_ERROR" wide ascii

                $pdb1 = "rouji\\release\\Install.pdb" wide ascii
                $pdb2 = "rouji\\SvcMain.pdb" wide ascii

        condition:
                (all of ($s*)) or (all of ($e*)) or $pdb1 or $pdb2
}
rule BOUNCER_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
                $s2 = "IDR_DATA%d" wide ascii

                $s3 = "asdfqwe123cxz" wide ascii
                $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii

        condition:
                ($s1 and $s2) or ($s3 and $s4)

}

rule GOGGLES_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}
rule BANGAT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
                $s8 = "end      binary output" wide ascii
                $s9 = "XriteProcessMemory" wide ascii
                $s10 = "IE:Password-Protected sites" wide ascii
                $s11 = "pstorec.dll" wide ascii

        condition:
                all of them
}
rule Crowdstrike_Shamoon
{ meta:
description = "Rule to catch Shamoon version A wiper."
strings:
$del1 = "dir \"C:\\Documents and Settings\\\" /s /b /a:-D 2>nul | findstr -i download 2>nul >f1.inf"
$del2 = "dir \"C:\\Documents and Settings\\\" /s /b /a:-D 2>nul | findstr -i document 2>nul >>f1.inf"
$del3 = "dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i download 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i document 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D2>nul | findstr -i picture 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i video 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i music 2>nul >>f1.inf dir \"C:\\Documents and Settings\\\" /s /b /a:-D 2>nul | findstr -i desktop 2>nul >f2.inf"
$del4 = "dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i desktop 2>nul >>f2.inf dir C:\\Windows\\System32\\Drivers /s /b /a:-D 2>nul >>f2.inf"
$del5 = "dir C:\\Windows\\System32\\Config /s /b /a:-D 2>nul | findstr -v - isystemprofile 2>nul >>f2.inf"
$del6 = "dir f1.inf /s /b 2>nul >>f1.inf dir f2.inf /s /b 2>nul >>f1.inf"
$del7 = { 64 69 72 20 22 43 3A 5C 44 6F 63 75 6D 65 6E 74 73 20 61 6E 64 20 53 65 74 74 69 6E 67 73 5C 22 20 2F 73 20 2F 62 20 2F 61 3A 2D 44 20 32 3E 6E 75 6C}
condition:
($del1 and $del2 and $del3 and $del4 and $del5 and $del6) or $del7 }

rule Trojan_W32_Gh0stMiancha_1_0_0
{
 strings:
 $0x = { 57 5b 5a 5a 51 57 40 34 31 67 2e 31 70 34 5c 40 40 44 3b 25 3a 19 1e 5c 7b 67 60 2e 34 31 67 2e 31 70 19 1e 55 77 77 71 64 60 2e 34 3e 3b 3e 19 1e 57 7b 7a 60 71 7a 60 39 40 6d 64 71 2e 34 60 71 6c 60 3b 7c 60 79 78 19 1e 44 66 7b 6c 6d 39 57 7b 7a 7a 71 77 60 7d 7b 7a 2e 34 5f 71 71 64 39 55 78 7d 62 71 19 1e 57 7b 7a 60 71 7a 60 39 78 71 7a 73 60 7c 2e 34 24 19 1e 19 1e }
 $1 = { 5c e7 99 bd e5 8a a0 e9 bb 91 5c }
 $1x = { 48 f3 8d a9 f1 9e b4 fd af 85 48 }
 $2 = "DllCanLoadNow"
 $2x = { 50 78 78 57 75 7a 58 7b 75 70 5a 7b 63 }
 $3x = { 5a 61 79 76 71 66 34 7b 72 34 67 61 76 7f 71 6d 67 2e 34 31 70 }
 $4 = "JXNcc2hlbGxcb3Blblxjb21tYW5k"
 $4x = { 5e 4c 5a 77 77 26 7c 78 76 53 6c 77 76 27 56 78 76 78 6c 7e 76 26 25 60 4d 43 21 7f }
 $5 = "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA=="
 $5x = { 47 51 52 47 46 52 70 56 41 7f 42 77 46 51 42 40 45 25 5e 5e 41 52 46 5e 40 24 21 77 41 27 78 6e 70 53 42 60 4c 51 5a 78 76 7a 46 6d 4d 43 6c 45 77 79 2d 7e 4e 4c 5a 6e 76 27 5e 77 59 55 29 29 }
 $6 = "C:\\Users\\why\\"
 $6x = { 57 2e 48 41 67 71 66 67 48 63 7c 6d 48 }
 $7 = "g:\\ykcx\\"
 $7x = { 73 2E 48 6D 7F 77 6C 48 }
 $8 = "(miansha)"
 $8x = { 3C 79 7D 75 7A 67 7C 75 3D }
 $9 = "server(\xE5\xA3\xB3)"
 $9x = { 7C 2E 48 26 24 25 27 3A 25 25 3A 26 21 48 67 71 66 62 71 66 3C F1 B7 A7 3D 48 46 71 78 71 75 67 71 48 67 71 66 62 71 66 3A 64 70 76 }
 $cfgDecode = { 8a ?? ?? 80 c2 7a 80 f2 19 88 ?? ?? 41 3b ce 7c ??}
 condition:
 any of them
}
rule backdoor_apt_pcclient
{
meta:
        author = "@patrickrolsen"
        maltype = "APT.PCCLient"
        filetype = "DLL"
        version = "0.1"
        description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
        date = "2012-10"
strings:
        $magic = { 4d 5a } // MZ
        $string1 = "www.micro1.zyns.com"
        $string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
        $string3 = "msacm32.drv" wide
        $string4 = "C:\\Windows\\Explorer.exe" wide
        $string5 = "Elevation:Administrator!" wide
        $string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"
condition:
        $magic at 0 and 4 of ($string*)
}


rule CrowdStrike_Shamoon_DroppedFile {
        meta:
                description = "Rule to detect Shamoon malware."

        strings:
                $testn123 = "test123" wide
                $testn456 = "test456" wide
                $testn789 = "test789" wide
                $testdomain = "testdomain.com" wide
                $pingcmd = "ping -n 30 127.0.0.1 >nul" wide

        condition:
                (any of ($testn*) or $pingcmd) and $testdomain
}
rule APT1_WEBC2_UGX
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $persis = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide ascii
        $exe = "DefWatch.exe" wide ascii
        $html = "index1.html" wide ascii
        $cmd1 = "!@#tiuq#@!" wide ascii
        $cmd2 = "!@#dmc#@!" wide ascii
        $cmd3 = "!@#troppusnu#@!" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_HEAD
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "Ready!" wide ascii
        $2 = "connect ok" wide ascii
        $3 = "WinHTTP 1.0" wide ascii
        $4 = "<head>" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_GREENCAT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "reader_sl.exe" wide ascii
        $2 = "MS80547.bat" wide ascii
        $3 = "ADR32" wide ascii
        $4 = "ControlService failed!" wide ascii
    condition:
        3 of them
}
rule APT1_MAPIGET
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $s1 = "%s\\Attachment.dat" wide ascii
        $s2 = "MyOutlook" wide ascii
        $s3 = "mail.txt" wide ascii
        $s4 = "Recv Time:" wide ascii
        $s5 = "Subject:" wide ascii

    condition:
        all of them
}

rule APT1_GETMAIL
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $stra1 = "pls give the FULL path" wide ascii
        $stra2 = "mapi32.dll" wide ascii
        $stra3 = "doCompress" wide ascii

        $strb1 = "getmail.dll" wide ascii
        $strb2 = "doCompress" wide ascii
        $strb3 = "love" wide ascii
    condition:
        all of ($stra*) or all of ($strb*)
}

rule APT1_WEBC2_YAHOO
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $http1 = "HTTP/1.0" wide ascii
        $http2 = "Content-Type:" wide ascii
        $uagent = "IPHONE8.5(host:%s,ip:%s)" wide ascii
    condition:
        all of them
}
rule EclipseSunCloudRAT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "Eclipse_A" wide ascii
    $b = "\\PJTS\\" wide ascii
    $c = "Eclipse_Client_B.pdb" wide ascii
    $d = "XiaoME" wide ascii
    $e = "SunCloud-Code" wide ascii
    $f = "/uc_server/data/forum.asp" wide ascii

  condition:
    any of them
}

rule ccrewSSLBack3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SLYHKAAY" wide ascii

  condition:
    any of them
}

rule metaxcd
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "<meta xcd=" wide ascii

  condition:
    $a
}
rule STARSYPOUND_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "*(SY)# cmd" wide ascii
                $s2 = "send = %d" wide ascii
                $s3 = "cmd.exe" wide ascii
                $s4 = "*(SY)#" wide ascii


        condition:
                all of them
}

rule SWORD_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "@***@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>>>" wide ascii
                $s2 = "sleep:" wide ascii
                $s3 = "down:" wide ascii
                $s4 = "*========== Bye Bye ! ==========*" wide ascii


        condition:
                all of them
}

rule Elise
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SetElise.pdb" wide ascii

  condition:
    $a
}
rule HACKSFASE1_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = {cb 39 82 49 42 be 1f 3a}

        condition:
                all of them
}

rule MACROMAIL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "svcMsn.dll" wide ascii
                $s2 = "RundllInstall" wide ascii
                $s3 = "Config service %s ok." wide ascii
                $s4 = "svchost.exe" wide ascii

        condition:
                all of them
}

rule SEASALT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.00; Windows 98) KSMM" wide ascii
                $s2 = "upfileok" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "upfileer" wide ascii
                $s5 = "fxftest" wide ascii


        condition:
                all of them
}
rule BISCUIT_GREENCAT_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "zxdosml" wide ascii
                $s2 = "get user name error!" wide ascii
                $s3 = "get computer name error!" wide ascii
                $s4 = "----client system info----" wide ascii
                $s5 = "stfile" wide ascii
                $s6 = "cmd success!" wide ascii

        condition:
                all of them
}

rule BOUNCER_DLL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "new_connection_to_bounce():" wide ascii
                $s2 = "usage:%s IP port [proxip] [port] [key]" wide ascii

        condition:
                all of them
}

rule CALENDAR_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "content" wide ascii
                $s2 = "title" wide ascii
                $s3 = "entry" wide ascii
                $s4 = "feed" wide ascii
                $s5 = "DownRun success" wide ascii
                $s6 = "%s@gmail.com" wide ascii
                $s7 = "<!--%s-->" wide ascii

                $b8 = "W4qKihsb+So=" wide ascii
                $b9 = "PoqKigY7ggH+VcnqnTcmhFCo9w==" wide ascii
                $b10 = "8oqKiqb5880/uJLzAsY=" wide ascii

        condition:
                all of ($s*) or all of ($b*)
}
rule APT1_dbg_mess
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $dbg1 = "Down file ok!" wide ascii
        $dbg2 = "Send file ok!" wide ascii
        $dbg3 = "Command Error!" wide ascii
        $dbg4 = "Pls choose target first!" wide ascii
        $dbg5 = "Alert!" wide ascii
        $dbg6 = "Pls press enter to make sure!" wide ascii
        $dbg7 = "Are you sure to " wide ascii
    condition:
        4 of them
}

rule APT1_aspnetreport
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $url = "aspnet_client/report.asp" wide ascii
        $param = "name=%s&Gender=%c&Random=%04d&SessionKey=%s" wide ascii
    condition:
        $url and $param
}


rule AURIGA_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
        condition:
                all of them
}
rule APT1_payloads
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $pay1 = "rusinfo.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii
    condition:
        1 of them
}
rule APT1_WEBC2_CSON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $httpa1 = "/Default.aspx?INDEX=" wide ascii
        $httpa2 = "/Default.aspx?ID=" wide ascii
        $httpb1 = "Win32" wide ascii
        $httpb2 = "Accept: text*/*" wide ascii
        $exe1 = "xcmd.exe" wide ascii
        $exe2 = "Google.exe" wide ascii
    condition:
        1 of ($exe*) and 1 of ($httpa*) and all of ($httpb*)
}

rule APT1_WEBC2_CLOVER
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $msg1 = "BUILD ERROR!" wide ascii
        $msg2 = "SUCCESS!" wide ascii
        $msg3 = "wild scan" wide ascii
        $msg4 = "Code too clever" wide ascii
        $msg5 = "insufficient lookahead" wide ascii
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; SV1)" wide ascii
        $ua2 = "Mozilla/5.0 (Windows; Windows NT 5.1; en-US; rv:1.8.0.12) Firefox/1.5.0.12" wide ascii
    condition:
        2 of ($msg*) and 1 of ($ua*)
}

rule APT1_WEBC2_ADSPACE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "<!---HEADER ADSPACE style=" wide ascii
        $2 = "ERSVC.DLL" wide ascii
    condition:
        all of them
}
rule APT1_WEBC2_TABLE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $msg1 = "Fail To Execute The Command" wide ascii
        $msg2 = "Execute The Command Successfully" wide ascii
        $gif1 = /\w+\.gif/
        $gif2 = "GIF89" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_RAVE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "iniet.exe" wide ascii
        $2 = "cmd.exe" wide ascii
        $3 = "SYSTEM\\CurrentControlSet\\Services\\DEVFS" wide ascii
        $4 = "Device File System" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_DIV
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "3DC76854-C328-43D7-9E07-24BF894F8EF5" wide ascii
        $2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $3 = "Hello from MFC!" wide ascii
        $4 = "Microsoft Internet Explorer" wide ascii
    condition:
        3 of them
}
rule ccrewSSLBack1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "!@#%$^#@!" wide ascii
    $b = "64.91.80.6" wide ascii

  condition:
    any of them
}

rule APT1_LIGHTBOLT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "bits.exe" wide ascii
        $str2 = "PDFBROW" wide ascii
        $str3 = "Browser.exe" wide ascii
        $str4 = "Protect!" wide ascii
    condition:
        2 of them
}

rule APT1_WEBC2_Y21K
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "Y29ubmVjdA" wide ascii // connect
        $2 = "c2xlZXA" wide ascii // sleep
        $3 = "cXVpdA" wide ascii // quit
        $4 = "Y21k" wide ascii // cmd
        $5 = "dW5zdXBwb3J0" wide ascii // unsupport
    condition:
        4 of them
}
rule NEWSREELS_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0)" wide ascii
                $s2 = "name=%s&userid=%04d&other=%c%s" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "noclient" wide ascii
                $s6 = "wait" wide ascii
                $s7 = "active" wide ascii
                $s8 = "hello" wide ascii


        condition:
                all of them
}

rule MoonProject
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "Serverfile is smaller than Clientfile" wide ascii
    $b = "\\M tools\\" wide ascii
    $c = "MoonDLL" wide ascii
        $d = "\\M tools\\" wide ascii

  condition:
    any of them
}

rule ccrewMiniasp
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "MiniAsp.pdb" wide ascii
    $b = "device_t=" wide ascii

  condition:
    any of them
}
rule DAIRY_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE 7.0;)" wide ascii
                $s2 = "KilFail" wide ascii
                $s3 = "KilSucc" wide ascii
                $s4 = "pkkill" wide ascii
                $s5 = "pklist" wide ascii


        condition:
                all of them
}

rule HACKSFASE2_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Send to Server failed." wide ascii
                $s2 = "HandShake with the server failed. Error:" wide ascii
                $s3 = "Decryption Failed. Context Expired." wide ascii

        condition:
                all of them
}

rule MINIASP_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "miniasp" wide ascii
                $s2 = "wakeup=" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "device_input.asp?device_t=" wide ascii


        condition:
                all of them
}
rule LIGHTDART_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "ret.log" wide ascii
                $s2 = "Microsoft Internet Explorer 6.0" wide ascii
                $s3 = "szURL Fail" wide ascii
                $s4 = "szURL Successfully" wide ascii
                $s5 = "%s&sdate=%04ld-%02ld-%02ld" wide ascii
        condition:
                all of them
}


rule COMBOS_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla4.0 (compatible; MSIE 7.0; Win32)" wide ascii
                $s2 = "Mozilla5.1 (compatible; MSIE 8.0; Win32)" wide ascii
                $s3 = "Delay" wide ascii
                $s4 = "Getfile" wide ascii
                $s5 = "Putfile" wide ascii
                $s6 = "---[ Virtual Shell]---" wide ascii
                $s7 = "Not Comming From Our Server %s." wide ascii


        condition:
                all of them
}
rule APT_NGO_wuaclt_PDF
{
        strings:
                $pdf  = "%PDF" nocase
                $comment = {3C 21 2D 2D 0D 0A 63 57 4B 51 6D 5A 6C 61 56 56 56 56 56 56 56 56 56 56 56 56 56 63 77 53 64 63 6A 4B 7A 38 35 6D 37 4A 56 6D 37 4A 46 78 6B 5A 6D 5A 6D 52 44 63 5A 58 41 73 6D 5A 6D 5A 7A 42 4A 31 79 73 2F 4F 0D 0A}

        condition:
                $pdf at 0 and $comment in (0..200)
}

rule APT_WIN_Gh0st_ver
{
meta:
   author = "@BryanNolen"
   source = "Yara Exchange"
   date = "2012-12"
   type = "APT"
   version = "1.1"
   ref = "Detection of Gh0st RAT server DLL component"
   ref1 = "http://www.mcafee.com/au/resources/white-papers/foundstone/wp-know-your-digital-enemy.pdf"
 strings:
   $library = "deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly"
   $capability = "GetClipboardData"
   $capability1 = "capCreateCaptureWindowA"
   $capability2 = "CreateRemoteThread"
   $capability3 = "WriteProcessMemory"
   $capability4 = "LsaRetrievePrivateData"
   $capability5 = "AdjustTokenPrivileges"
   $function = "ResetSSDT"
   $window = "WinSta0\\Default"
   $magic = {47 6C 6F 62 61 6C 5C [5-9] 20 25 64}    /* $magic = "Gh0st" */
 condition:
   all of them
}
private rule APT1_RARSilent_EXE_PDF
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $winrar1 = "WINRAR.SFX" wide ascii
        $winrar2 = ";The comment below contains SFX script commands" wide ascii
        $winrar3 = "Silent=1" wide ascii

        $str1 = /Setup=[\s\w\"]+\.(exe|pdf|doc)/
        $str2 = "Steup=\"" wide ascii
    condition:
        all of ($winrar*) and 1 of ($str*)
}

rule APT1_known_malicious_RARSilent
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "Analysis And Outlook.doc\"" wide ascii
        $str2 = "North Korean launch.pdf\"" wide ascii
        $str3 = "Dollar General.doc\"" wide ascii
        $str4 = "Dow Corning Corp.pdf\"" wide ascii
    condition:
        1 of them and APT1_RARSilent_EXE_PDF
}

rule APT_NGO_wuaclt
{
  strings:
    $a = "%%APPDATA%%\\Microsoft\\wuauclt\\wuauclt.dat"
    $b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $c = "/news/show.asp?id%d=%d"
    $d = "%%APPDATA%%\\Microsoft\\wuauclt\\"
    $e = "0l23kj@nboxu"
    $f = "%%s.asp?id=%%d&Sid=%%d"
    $g = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SP Q%%d)"
    $h = "Cookies: UseID=KGIOODAOOK%%s"

  condition:
    ($a and $b and $c) or ($d and $e) or ($f and $g and $h)
}
rule APT1_TARSIP_ECLIPSE
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "\\pipe\\ssnp" wide ascii
        $2 = "toobu.ini" wide ascii
        $3 = "Serverfile is not bigger than Clientfile" wide ascii
        $4 = "URL download success" wide ascii
    condition:
        3 of them
}

rule APT1_TARSIP_MOON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $s1 = "\\XiaoME\\SunCloud-Code\\moon" wide ascii
        $s2 = "URL download success!" wide ascii
        $s3 = "Kugoosoft" wide ascii
        $msg1 = "Modify file failed!! So strange!" wide ascii
        $msg2 = "Create cmd process failed!" wide ascii
        $msg3 = "The command has not been implemented!" wide ascii
        $msg4 = "Runas success!" wide ascii
        $onec1 = "onec.php" wide ascii
        $onec2 = "/bin/onec" wide ascii
    condition:
        1 of ($s*) and 1 of ($msg*) and 1 of ($onec*)
}
rule APT1_WEBC2_KT3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "*!Kt3+v|" wide ascii
        $2 = " s:" wide ascii
        $3 = " dne" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_BOLID
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $vm = "VMProtect" wide ascii
        $http = "http://[c2_location]/[page].html" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_AUSOV
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "ntshrui.dll" wide ascii
        $2 = "%SystemRoot%\\System32\\" wide ascii
        $3 = "<!--DOCHTML" wide ascii
        $4 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" wide ascii
        $5 = "Ausov" wide ascii
    condition:
        4 of them
}
rule APT1_GDOCUPLOAD
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "name=\"GALX\"" wide ascii
        $str2 = "User-Agent: Shockwave Flash" wide ascii
        $str3 = "add cookie failed..." wide ascii
        $str4 = ",speed=%f" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_TOCK
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "InprocServer32" wide ascii
        $2 = "HKEY_PERFORMANCE_DATA" wide ascii
        $3 = "<!---[<if IE 5>]id=" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_QBP
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "2010QBP" wide ascii
        $2 = "adobe_sl.exe" wide ascii
        $3 = "URLDownloadToCacheFile" wide ascii
        $4 = "dnsapi.dll" wide ascii
        $5 = "urlmon.dll" wide ascii
    condition:
        4 of them
}
rule ccrewDownloader1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = {DD B5 61 F0 20 47 20 57 D6 65 9C CB 31 1B 65 42}

  condition:
    any of them
}

rule ccrewSSLBack2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = {39 82 49 42 BE 1F 3A}

  condition:
    any of them
}

rule ccrewDownloader3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "ejlcmbv" wide ascii
        $b = "bhxjuisv" wide ascii
        $c = "yqzgrh" wide ascii
        $d = "uqusofrp" wide ascii
        $e = "Ljpltmivvdcbb" wide ascii
        $f = "frfogjviirr" wide ascii
        $g = "ximhttoskop" wide ascii
  condition:
    4 of them
}
rule TABMSGSQL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "letusgohtppmmv2.0.0.1" wide ascii
                $s2 = "Mozilla/4.0 (compatible; )" wide ascii
                $s3 = "filestoc" wide ascii
                $s4 = "filectos" wide ascii
                $s5 = "reshell" wide ascii

        condition:
                all of them
}

rule TrojanCookies_CCREW
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "sleep:" wide ascii
    $b = "content=" wide ascii
    $c = "reqpath=" wide ascii
    $d = "savepath=" wide ascii
    $e = "command=" wide ascii


  condition:
    4 of ($a,$b,$c,$d,$e)
}
rule GLOOXMAIL_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule KURTON_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE8.0; Windows NT 5.1)" wide ascii
                $s2 = "!(*@)(!@PORT!(*@)(!@URL" wide ascii
                $s3 = "MyTmpFile.Dat" wide ascii
                $s4 = "SvcHost.DLL.log" wide ascii

        condition:
                all of them
}

rule thequickbrow_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "thequickbrownfxjmpsvalzydg" wide ascii


        condition:
                all of them
}
rule GeorBotMemory {

strings:
        $a = {53 4F 46 54 57 41 52 45 5C 00 4D 69 63 72 6F 73 6F 66 74 5C 00 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 00 52 75 6E 00 55 53 42 53 45 52 56}
        $b = {73 79 73 74 65 6D 33 32 5C 75 73 62 73 65 72 76 2E 65 78 65}
        $c = {5C 75 73 62 73 65 72 76 2E 65 78 65}

condition:
        $a and ($b or $c)

}

rule GeorBotBinary {

strings:
        $a = {63 72 ?? 5F 30 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C}

condition:
        all of them
}


rule AURIGA_driver_APT1 {
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

        strings:
                $s1 = "Services\\riodrv32" wide ascii
                $s2 = "riodrv32.sys" wide ascii
                $s3 = "svchost.exe" wide ascii
                $s4 = "wuauserv.dll" wide ascii
                $s5 = "arp.exe" wide ascii
                $pdb = "projects\\auriga" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule Win32_SwizzorA_Variants_siggen_1
{
strings:
        $a0 = { 0068 }
        $a1 = { 33f6 }
        $a2 = { 0400 }
        $a3 = { 8bff }
        $a4 = { 3bde7405 }
        $a5 = { 0400 }
        $a6 = { 33c0 }
        $a7 = { 0400 }
        $a8 = { 0400 }
        $a9 = { 0400 }
        $a10 = { 0400 }
        $a11 = { 8bff }
        $a12 = { 885f14 }
        $a13 = { 85f67405 }
        $a14 = { 0400 }
        $a15 = { 0400 }
        $a16 = { 3b16753d }
        $a17 = { 8937 }
        $a18 = { 890e }
        $a19 = { 0400 }
        $a20 = { 8b1b }
        $a21 = { 8b1b }
        $a22 = { 8bc3 }
        $a23 = { 8b1b }
        $a24 = { 33c0 }
        $a25 = { 6a24e8 }
        $a26 = { 0068 }
        $a27 = { 0400 }
        $a28 = { 33c0 }
        $a29 = { 0400 }
        $a30 = { 893e }
        $a31 = { 6a24e8 }
        $a32 = { 33c0 }
        $a33 = { 3bde7405 }
        $a34 = { 0068 }
        $a35 = { 33c0 }
        $a36 = { 0068 }
        $a37 = { 33c0 }
        $a38 = { 0400 }
        $a39 = { 0400 }
        $a40 = { 8b3febcd }
        $a41 = { 0400 }
        $a42 = { 0400 }
        $a43 = { 00e8 }
        $a44 = { 00c706 }
        $a45 = { 50e8 }
        $a46 = { 5ec3 }
        $a47 = { 8d470485c07405 }
        $a48 = { c20800 }
        $a49 = { 007407 }
        $a50 = { 00c706 }
        $a51 = { 53e8 }
        $a52 = { 00e8 }
        $a53 = { 040083c404 }
        $a54 = { 0400 }
        $a55 = { 0400 }
        $a56 = { 0085c0753d }
        $a57 = { 8bc8e8 }
        $a58 = { 005ec3 }
        $a59 = { 0068 }
        $a60 = { 56ff }
        $a61 = { 89780c8b4f }
        $a62 = { 56e8 }
        $a63 = { 6a18e8 }
        $a64 = { c74004 }
        $a65 = { 00eb02 }
        $a66 = { 33c0 }
        $a67 = { 85db742e }
        $a68 = { 5dc3 }
        $a69 = { ff15 }
        $a70 = { 33c0 }
        $a71 = { ff15 }
        $a72 = { 51ff15 }
        $a73 = { 0400 }
        $a74 = { 53e8 }
        $a75 = { 50e8 }
        $a76 = { 0400 }
        $a77 = { 0400 }
        $a78 = { 0400 }
        $a79 = { 0400 }
        $a80 = { 8d4900 }
        $a81 = { 0400 }
        $a82 = { 6aff68 }
        $a83 = { 0400 }
        $a84 = { 0400 }
        $a85 = { 33f6eb0a }
        $a86 = { 33c9eb08 }
        $a87 = { 33c0eb08 }
        $a88 = { 8bd18b09 }
        $a89 = { 8079150074ec }
        $a90 = { 737f }
        $a91 = { 3b067405 }
        $a92 = { 00c74604 }
        $a93 = { 00c701 }
        $a94 = { 894608 }
        $a95 = { 33c0 }
        $a96 = { 5f5e }
        $a97 = { 83c001 }
        $a98 = { 088b }
        $a99 = { 83c001 }
        $a100 = { 83c4 }
        $a101 = { 240c8d74 }
        $a102 = { 33c9 }
        $a103 = { 0128 }
        $a104 = { 5650ff15 }
        $a105 = { 55b9 }
        $a106 = { ffff }
        $a107 = { 8bd6 }
        $a108 = { 8dffff }
        $a109 = { 8b15 }
        $a110 = { 2bc2 }
        $a111 = { 008b500cb9 }
        $a112 = { 0033149d }
        $a113 = { 8b542414 }
        $a114 = { c74620 }
        $a115 = { 395f047705 }
        $a116 = { 5550e8 }
        $a117 = { ffff }
        $a118 = { 8bff }
        $a119 = { 03d8 }
        $a120 = { 33dbeb1f }
        $a121 = { 0400 }
        $a122 = { 0400 }
        $a123 = { 00e8 }
        $a124 = { 6aff68 }
        $a125 = { ffff }
        $a126 = { 6a40e801 }
        $a127 = { 6a50e881 }
        $a128 = { 33c0a3 }
        $a129 = { 3935 }
        $a130 = { 8325 }
        $a131 = { 8b0d }
        $a132 = { 390d }
        $a133 = { 33c0 }
        $a134 = { 6a03 }
        $a135 = { 7508 }
        $a136 = { 85c9742b }
        $a137 = { 7307 }
        $a138 = { 3b1d }
        $a139 = { 0f8cad000000 }
        $a140 = { 3bd07c08 }
        $a141 = { 7508 }
        $a142 = { 8b0d }
        $a143 = { 4a83cae042 }
        $a144 = { 33c0 }
        $a145 = { aba1 }
        $a146 = { 3c5a740a }
        $a147 = { 8ac3 }

condition:
        $a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52 and $a53 and $a54 and $a55 and $a56 and $a57 and $a58 and $a59 and $a60 and $a61 and $a62 and $a63 and $a64 and $a65 and $a66 and $a67 and $a68 and $a69 and $a70 and $a71 and $a72 and $a73 and $a74 and $a75 and $a76 and $a77 and $a78 and $a79 and $a80 and $a81 and $a82 and $a83 and $a84 and $a85 and $a86 and $a87 and $a88 and $a89 and $a90 and $a91 and $a92 and $a93 and $a94 and $a95 and $a96 and $a97 and $a98 and $a99 and $a100 and $a101 and $a102 and $a103 and $a104 and $a105 and $a106 and $a107 and $a108 and $a109 and $a110 and $a111 and $a112 and $a113 and $a114 and $a115 and $a116 and $a117 and $a118 and $a119 and $a120 and $a121 and $a122 and $a123 and $a124 and $a125 and $a126 and $a127 and $a128 and $a129 and $a130 and $a131 and $a132 and $a133 and $a134 and $a135 and $a136 and $a137 and $a138 and $a139 and $a140 and $a141 and $a142 and $a143 and $a144 and $a145 and $a146 and $a147
}

rule W97M_Bptk_B
{
strings:
        $a0 = { 53657420??203d204e6f726d616c54656d706c6174652e564250726f6a6563742e5642436f6d706f6e656e74732e4974656d283129 }
        $a1 = { 2e44656c6574654c696e657320312c20 }
        $a2 = { 2e436f756e744f664c696e6573 }
        $a3 = { 2e41646446726f6d??7472696e6720 }
        $a4 = { 2e4c696e657328312c20 }
        $a5 = { 2e436f756e744f664c696e657329 }
        $a6 = { 416374697665446f63756d656e742e53617665 }

condition:
        $a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6
}

rule W97M_Thus_BI
{
strings:
        $a0 = { 53756220436f70794d654d652829 }
        $a1 = { 4974656d2831292e436f64654d6f64756c652e4c696e657328332c203129203d202227 }
        $a2 = { 74732869292e46756c6c4e616d65203c3e20746869736e2420546865 }
        $a3 = { 616e697a6572436f707920536f757263653a3d20 }
        $a4 = { 746869736e242c2044657374696e6174696f6e3a3d20 }
        $a5 = { 446f63756d656e74732869292e46756c6c4e }

condition:
        $a0 and $a1 and $a2 and $a3 and $a4 and $a5
}

rule Exploit_CVE_2010_0188
{
strings:
        $a0 = { 070000010300010000003020000001010300010000000100000003010300010000000100000006010300010000000100000011010400010000000800000017010400010000003020000050010300cc0000009220000000000000000c0c0824010100????000704010100bb150007001000004d150007bb1500070003fe7fb27f0007bb15000711000100aca80007bb15000700010100aca80007????000711000100e2520007545c0007ffffffff000101000000000004010100001000004000000031d70007bb1500075a526a024d15000722a70007bb15000758cd2e3c4d15000722a70007bb150007055a74f44d15000722a70007bb150007b849492a4d15000722a70007bb150007008bfaaf4d15000722a70007bb15000775ea87fe4d15000722a70007bb150007eb0a5fb94d15000722a70007bb150007e00300004d15000722a70007bb150007f3a5eb094d15000722a70007bb150007e8f1ffff4d15000722a70007bb150007ff9090904d15000722a70007bb150007ffffff904d15000731d700072f110007 }

condition:
        $a0
}

rule Adware_EliteBar
{
strings:
        $a0 = { 8b4cc706d0767cce816d898e480508017484138bc65e0d83c410c2080090ee2d1760007c013a9bf6080174095645b7089d4104370517d5c204d3fa5ce7ae743c4f5604c7397d789a26fb61eda493607b8bceaec02274ff99f46c34355b0616afc3909b008f30578b7c8d86006a1748506a01574783c668566a0273b6f1b25f9f708483b8b08db0b8c5535657 }

condition:
        $a0
}

rule Exploit_Apache_2
{
strings:
        $a0 = { 5589e583ec3866c745e802008b4508890424e85ff8ffff8945ec0fb7450c890424e830f9ffff668945eac744240800000000c744240401000000c7042402000000e860f9ffff8945e4837de4007f21c7042451ae0408e87bfaffffc7042405000000e8dff7ffffc745e0feffffffeb2d }
        $a1 = { 736c2d746f6f2d6f70656e2e63202d204f70 }

condition:
        $a0 and $a1
}


rule Exploit_Apache_1
{
strings:
        $a0 = { 83c4f48b450c83c0048b1052e867fdffff83c41089c08b55f48b4df889cb89d9c1e10481c200a400008904118b45f48b55f889d189cac1e2040504a400008b4df081c1d0d5ffff890c028b45f48b4df889cac1e20201cac1e20301ca8d0c9500000000c644010602ff45f8eb838d760083c4f88b450c83c0048b105268b78b0408e8b2fcffff83c41031c0eb038d }
        $a1 = { 656e73736c5f6578706c6f }

condition:
        $a0 and $a1
}


rule Exploit_Bonk
{
strings:
        $a0 = { 5589e583ec2883c4fca1689c0408506a0068a09d0408e82dfeffff83c4108025a09d04080f800da09d0408408025a09d0408f0800da09d04080583c4f466a15c9c0408668b15609c040801d08d501c31c06689d050e8defdffff }
        $a1 = { 67653a202e2f626f696e6b203c7372635f61 }

condition:
        $a0 and $a1
}

rule EleonoreExploitPackLink
{

 strings:
            $exemple1 = /http:\/\/.+?\/exemple.com\/load.php\?/  nocase
            $exemple2 = /http:\/\/.+?load.php\?spl=/   nocase
 condition:
          1 of them
}

rule MaliciousCodeInjection
{
 strings:
$malcode1 = "uy7gdr5332rkmn"
$malcode2 = "uy7gdr5kmn"
condition:
          1 of them
}

rule  Phoenix2ExploitPack
{
 strings:

         $phoenix = "<applet code='dev.s.AdgredY.class' archive='tmp/des.jar' width='462' height='255'>"

 condition:
          1 of them
}



rule EleonoreExploitPack
{
strings:
            $exploitpack = "code='bpac.a.class'"
//            $applet = "<applet"
            $archive = "archive="
 condition:
         all of them
}

rule  EleonoreExploitPack2
{
strings:
         $expstring = "block;overflow:hidden;width:0;height:0;left:0px;position:absolute;top:0px"

condition:
1 of them
}

rule BlackHoleExploitPack
{
strings:
         $balckstring1 = "<applet code='direct.bear.class' archive='./games/javaobe.jar'>"
         $blackstring2 = ".co.cc/index.php?tp"

condition:
1 of them
}


rule  MaliciousJSInjection
{
strings:
         $expstring =  "document.location.href='http://yagizmo.com/'"

condition:
1 of them
}




rule  MaliciousWordpressInjection
{
strings:
         $expstring =  "<script language=JavaScript>function decrypt_p(x){var l=x.length,b=1024,i,j,r,p=0,s=0,w=0,t=Array"

condition:
1 of them
}


rule  EICAR_Signature: virus test
{
        meta:
                ref = "AV TEST: EICAR Signature"
        impact = 0
                hide = true
strings:
         $eicarstring = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

condition:
1 of them
}

rule IE_Homepage_Hijack
{

strings:

$h1 = "document.createElement(Chr(111) & Chr(98) & Chr(106) & Chr(101) & Chr(99) & Chr(116))"
$h2 = "reg.regwrite jkf & nxjkv,xisi"

condition:
all of them
}

rule Malicious_URL_A
{
strings:
$m =
/http:\/\/.+?QQkFBg0([ABCDEFGHIJMNQUYcgkw0]{9})EkcJBQYN([ABCDEFGHIJMNQUYcgkw0]{10})/
condition:
1 of them

}

rule Malicious_Iframe_B
{
strings:
$m = /<iframe.+?http:\/\/.+?\.(c[oz]|vv)\.cc\/.+?(width=['"][01]["']|height=['"][01]['"]).+?<\/iframe>/  nocase
condition:
1 of them

}



rule Known_Obfuscated_Malicious_Javascript_D
{
strings:
$m = /<script.+?KLiHKYfJYrNAaLJ.+?JcHHoKmHL.+?K5JANHYL.*?<\/script>/
condition:
1 of them

}

rule Known_Obfuscated_Malicious_Javascript_C
{
strings:
$m = /<script.+?hvtwt7p.+?7syavpwey.+?oVdVyV.*?<\/script>/
condition:
1 of them

}

rule Known_Obfuscated_Malicious_Javascript_B
{
strings:
$m = /<script.+?YxfRQZcJr.+?fwmuagM.+?ryoADKY.*?<\/script>/
condition:
1 of them

}

rule Known_Obfuscated_Malicious_Javascript_A
{
strings:
$m = /<script.+?function\syJ.+?hjeIaIdI.+?bGiKlAiKtHyH.*?<\/script>/
condition:
1 of them

}

rule AllinOne_Exploit
{
strings:
$m = /5d7u%00f8u%af03u%000cu%9518u%28b8u%261au%5500u%4415u/

condition:
1 of them

}

rule JAVA_Exploit_A
{
strings:
$m =  /<applet.+?code=.+?value=.?[RM][Sj][Sj][=d][,o][T#][T#].+?<\/applet>/
condition:
1 of them

}

rule Phoenix_Exploit_Kit_Redirect
{
strings:
$m = ".info/tass.php?S=1"
condition:
1 of them
}


rule Exploit_Kit_Redirect
{
strings:
$m = "forum.php?tp="
condition:
1 of them
}

rule Phoenix_Exploit_Link
{
strings:
$m = ".php?s=IBBAA"
condition:
1 of them
}

private rule Null_Byte
{
strings:
$m = { 00 }
condition:
#m > 10

}


private rule All_Script
{
strings:
$m = /<script(?:.|\\r|\\n)*?[^<]*?[^>]*?(\/>|<\/script>)/  nocase
condition:
1 of them

}

rule Exploit_HTML_CodeBase_A
{
strings:
        $a0 = { 3c6f626a656374206e616d653d22782220636c61737369643d22636c7369643a31313132303630372d313030312d313131312d313030302d3131303139393930313132332220636f6465626173653d22 }

condition:
        $a0
}

rule Exploit_JS_DEPbypass_1
{
strings:
        $a0 = { 3b646f63756d656e742e777269746528223c68323e7368656c6c636f64653a3c2f68323e22293b766172206e3032323d6f6861766f632e686578737472696e67282239302039302039302039302065622034332035362035372038622034352033632038622035342030352037382030312065612035322038622035 }

condition:
        $a0
}

rule Exploit_Iframe_1
{
strings:
        $a0 = { 3c2f696672616d653e3c696672616d65207372633d[0-50]77696474683d30206865696768743d303e3c2f696672616d653e }

condition:
        $a0
}

rule Exploit_HTML_VML_10
{
strings:
        $a0 = { 6d6574686f643d22262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b262378303630363b26237830 }

condition:
        $a0
}

rule Exploit_HTML_ObjCode
{
strings:
        $a0 = { 3c68746d6c3e3c6f626a656374206e616d653d22782220636c61737369643d22636c7369643a31313131313131312d313131312d313131312d313131312d3131313131313131313132332220636f6465626173653d2263616c632e657865223e3c2f68746d6c3e }

condition:
        $a0
}

rule Exploit_GDS
{
strings:
        $a0 = { 28223132372e302e302e313a343636342f73656172636826733d282e2b3f295c3f7122293b76617272657265733d72652e6578656328646f63756d656e742e7374796c657368656574732830292e696d706f7274732830292e63737374657874293b6966287265726573297b2f2f73686f777468657061727365646b6579646f63756d656e742e676574656c656d656e746279696428226764736b65792229 }

condition:
        $a0
}

rule Exploit_HTML_ObjCode_2
{
strings:
        $a0 = { 3e3c6f626a6563742077696474683d30206865696768743d30207374796c653d22646973706c61793a6e6f6e653b2220747970653d226170706c69636174696f6e2f782d6f6c656f626a6563742220636f6465626173653d22[0-5]2e657865223e3c2f6f626a6563743e }

condition:
        $a0
}

rule Exploit_MS05_001_gen
{
strings:
        $a0 = { 636c61737369643d22636c7369643a61646238383061362d643866662d313163662d393337372d30306161303033623761313122 }
        $a1 = { 76616c75653d22636f6d6d616e643b6a6176617363726970743a }

condition:
        $a0 and $a1
}

rule Exploit_Helpcontrol
{
strings:
        $a0 = { 636c7369643a61646238383061362d643866662d313163662d393337372d303061613030336237613131[10-20]6f6d6d616e64[6-15]52656c6174656420546f70696373[2-80]4974656d31 }
        $a1 = { 646f63756d656e742e7772697465 }

condition:
        $a0 and $a1
}

rule Exploit_HTML_MHTRedir
{
strings:
        $a0 = { 6d68746d6c222b223a222b2266696c653a2f2f[1-20]2168 }

condition:
        $a0
}

rule Exploit_HTML_ObjID
{
strings:
        $a0 = { 6e616d653d6874615f6e616d652073686f77696e7461736b6261723d6e6f2077696e646f7773746174653d6d696e696d697a65202f3e3c2f686561643e3c6f626a6563742069643d227773682220636c61737369643d22636c7369643a66393335646332322d316366302d313164302d616462392d303063303466643538613062223e }

condition:
        $a0
}
















