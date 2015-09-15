rule _barbar_update.msi {
        meta:
                description = "Generic rule for barbar dropped file - update.msi"
                author = "Es07er1K"
                reference = "http://www.spiegel.de/media/media-35683.pdf"
                date = "2015/02/20"
                hash = "1c755150b2803ae2afbd5c45abe9402a69d36b09"
        strings:
                $s0 = "NameTableColumnIdentifier_ValidationValueNPropertyId_SummaryInformationDescripti" ascii
                $s1 = "Windows Installer XML v3.0.2925.0" fullword ascii
                $s2 = "Installation Database" fullword ascii
                $s3 = ",Digital ID Class 3 - Netscape Object Signing1" fullword ascii
                $s4 = "Copyright 2007-2009 Google Inc." fullword ascii
                $s5 = "\"\"\")))***++++++111>>>>>>>>MMRRRRRRRR```aaabbbbbbnnppvv}}}}}}" fullword wide
                $s6 = "4^7iNo9" fullword ascii
                $s7 = "Google Update Helper" fullword ascii
                $s8 = "Google Inc0" fullword ascii
                $s9 = "Google Inc1503" fullword ascii
                $s10 = "$&($&($&(5,/2489;=DJL?ACFHOQ_^TSWY[]$&($&(dfhjlo|{ruxz" fullword wide
                $s11 = "{94EBC04C-25E4-43BB-8A3C-65A895389C20}" fullword ascii
                $s12 = "03>@BEGNP'3PRUXZ\\#%'#%'cegikm" fullword wide
                $s13 = "EG03NPRPUXZ\\3'#%'#%'cegikmn" fullword wide
                $s14 = "`GOLa" fullword ascii
                $s15 = "#%'#%'#%'%+-0361:<" fullword wide
                $s16 = "#%'#%'#%'+-03%61:<>@B" fullword wide
                $s17 = "dNG:9 " fullword ascii
                $s18 = "atHl0O" fullword ascii
                $s19 = "AUSenk" fullword ascii
                $s20 = "alNIf>4f" fullword ascii
        condition:
                all of them
}
rule _barbar_perf_585 {
        meta:
                description = "Generic rule for barbar dropped file - perf_585.dll"
                author = "Es07er1K"
                reference = "http://www.spiegel.de/media/media-35683.pdf"
                date = "2015/02/20"
                hash = "efbe18eb8a66e4b6289a5c53f22254f76e3a29bd"
        strings:
                $s0 = "Please report it to me at: jseward@acm.org.  If this happened" fullword ascii
                $s1 = "User-Agent: Mozilla/4.0 (compatible; MSI 6.0; Windows NT 5.1; .NET CLR 1.0.3705;" ascii
                $s2 = "Pre_Process_init: invalid parameter" fullword ascii
                $s3 = "\\Users\\*" fullword ascii
                $s4 = "Pre_Process_reset: invalid parameter" fullword ascii
                $s5 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
                $s6 = "/s /n %s \"%s\"" fullword ascii
                $s7 = "/c start /wait %s %s && del %s" fullword ascii
                $s8 = "Content-Type: binary/octet-stream" fullword ascii
                $s9 = "block %d: crc = 0x%8x, combined CRC = 0x%8x, size = %d" fullword ascii
                $s10 = "Pre_Process_init: can not malloc state structure" fullword ascii
                $s11 = "Speech_Encode_Frame_reset: invalid parameter" fullword ascii
                $s12 = "firefox.exe" fullword ascii
                $s13 = "\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
                $s14 = "%%WINDIR%%\\%s\\%s" fullword ascii
                $s15 = "\\Documents and Settings\\*" fullword ascii
                $s16 = "http%s://%s:%u%s" fullword ascii
                $s17 = "Speech_Encode_Frame_init: can not malloc state structure" fullword ascii
                $s18 = "quality software.  Thanks.  Julian Seward, 30 December 2001." fullword ascii
                $s19 = "combined CRCs: stored = 0x%x, computed = 0x%x" fullword ascii
                $s20 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
        condition:
                all of them
}
rule _barbar_48fe7f28 {
        meta:
                description = "Generic rule for barbar dropped file - 48fe7f28.msi"
                author = "Es07er1K"
                reference = "http://www.spiegel.de/media/media-35683.pdf"
                date = "2015/02/20"
                hash = "76bd9170a06657a89ccdfaa131b8cdf76d2a93fe"
        strings:
                $s0 = "PROikt" fullword ascii
        condition:
                all of them
}
rule _barbar_barbar {
        meta:
                description = "Generic rule for barbar file - Barbar.exe"
                author = "Es07er1K"
                reference = "http://www.spiegel.de/media/media-35683.pdf"
                date = "2015/02/20"
                hash = "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"
        strings:
                $s0 = "c:\\Documents and Settings\\admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper Re" ascii
                $s1 = "/s /n %s \"%s\"" fullword ascii
                $s2 = "%%WINDIR%%\\%s\\%s" fullword ascii
                $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
                $s4 = "System32" fullword ascii
                $s5 = "x0%it[" fullword ascii
                $s6 = "|nD?@" fullword ascii
                $s7 = "/c start /wait " fullword ascii
                $s8 = "w&]^$i" fullword ascii
                $s9 = "H8:A,1'\\" fullword ascii
                $s10 = "4c~,1,1H." fullword ascii
                $s11 = "g< [)O" fullword ascii
                $s12 = "-aNg=`" fullword ascii
                $s13 = "C+E'r0@" fullword ascii
                $s14 = "w_]@E&7" fullword ascii
                $s15 = "%COMMON_APPDATA%" fullword ascii
                $s16 = "/u /i:-\"" fullword ascii
                $s17 = "7chi#/" fullword ascii
                $s18 = "d.afS=" fullword ascii
                $s19 = "9~u3S]_" fullword ascii
                $s20 = "\"H/$i5" fullword ascii
        condition:
                all of them
}
rule wbemprox {
        meta:
                description = "Generic rule for barbar dropped file - wbemprox.log"
                author = "Es07er1K"
                reference = "http://www.spiegel.de/media/media-35683.pdf"
                date = "2015/02/20"
                hash = "08835eb0bc7a1be1b9ec5d7ac397edac17604b53"
        strings:
                $s0 = "(Sat Oct 01 13:29:36 2005.69630) : NTLMLogin resulted in hr = 0x8004100e" fullword ascii
                $s1 = "(Sat Oct 01 14:12:31 2005.25156) : NTLMLogin resulted in hr = 0x8004100e" fullword ascii
                $s2 = "(Sat Oct 01 12:55:57 2005.1008019) : NTLMLogin resulted in hr = 0x8004100e" fullword ascii
                $s3 = "(Fri Feb 20 16:01:31 2015.22986592) : NTLMLogin resulted in hr = 0x8004100e" fullword ascii
                $s4 = "(Fri Feb 20 16:01:30 2015.22985491) : NTLMLogin resulted in hr = 0x8004100e" fullword ascii
                $s5 = "(Fri Feb 20 16:01:30 2015.22985461) : NTLMLogin resulted in hr = 0x8004100e" fullword ascii
        condition:
                all of them
}