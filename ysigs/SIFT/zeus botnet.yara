rule Windows_Malware : Zeus_1134
    {
            meta:
                    author = "Xylitol xylitol@malwareint.com"
                    date = "2014-03-03"
                    description = "Match first two bytes, protocol and string present in Zeus 1.1.3.4"
                    reference = "http://www.xylibox.com/2014/03/zeus-1134.html"
                    yaraexchange = "do what the fuck you want"
            strings:
                    $mz = {4D 5A}
                    $protocol1 = "X_ID: "
                    $protocol2 = "X_OS: "
                    $protocol3 = "X_BV: "
                    $stringR1 = "InitializeSecurityDescriptor"
                    $stringR2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
            condition:
                    ($mz at 0 and all of ($protocol*) and ($stringR1 or $stringR2))
    }
	
rule xmlc : banker
{
    strings: 
        $a = "/c del" fullword
        $b = "PostDel" fullword
        $c = ">> NUL" fullword
        $d = "LOADXML"
        $e = "lm.dat"
        $f = "---------------%s----------------"

    condition:
        filesize < 150KB and (3 of ($a,$b,$c,$d,$e,$f))      
}

rule silent_banker : banker
{
    strings: 
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}  
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}

rule zbot : banker
{
     strings: 
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}

rule banbra : banker
{
    strings: 
        $a = "senha" fullword nocase
        $b = "cartao" fullword nocase
        $c = "caixa" 
        $d = "login" fullword nocase
        $e = ".com.br"

     condition:
        #a > 3 and #b > 3 and #c > 3 and #d > 3 and #e > 3              
}



rule spyeye
{
        meta:
        description = "Indicates that the SpyEye Trojan is installed"

        strings:
        $a = "SPYNET"
        $b = "SpyEye"

        condition:
        ($a and $b)
}

rule tdl3
{
        meta:
        null_string = 1

        strings:
        $1 = "\\\\?\\globalroot\\"
        $2 = ".ini" 

        condition:
        all of them
}

		
rule Windows_Malware : Zeus_1134
    {
            meta:
                    author = "Xylitol xylitol@malwareint.com"
                    date = "2014-03-03"
                    description = "Match first two bytes, protocol and string present in Zeus 1.1.3.4"
                    reference = "http://www.xylibox.com/2014/03/zeus-1134.html"
                    
            strings:
                    $mz = {4D 5A}
                    $protocol1 = "X_ID: "
                    $protocol2 = "X_OS: "
                    $protocol3 = "X_BV: "
                    $stringR1 = "InitializeSecurityDescriptor"
                    $stringR2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
            condition:
                    ($mz at 0 and all of ($protocol*) and ($stringR1 or $stringR2))
    }

rule Zeus_2
{
  strings: 
  $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??}
  $b = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ??}
  $c = {55 8B EC 51 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 56 8D 34 01 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??}
  $d = {68 02 01 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??}
    $e = {68 02 01 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 E6 01 00 00 50 68 ?? ?? ?? ??}
  condition:
 	$a or $b or $c or $d or $e
}

