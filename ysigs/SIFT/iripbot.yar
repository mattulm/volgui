rule Bannerjack {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho BannerJack hacktool”
	strings:
		$str _ 1 = “Usage: ./banner-jack [options]”
		$str _ 2 = “-f: file.csv”
		$str _ 3 = “-s: ip start”
		$str _ 4 = “-R: timeout read (optional, default %d secs)”
	condition:
		all of them
}

rule Eventlog {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho Eventlog hacktool”
	strings:
		$str _ 1 = “wevtsvc.dll”
		$str _ 2 = “Stealing %S.evtx handle ...”
		$str _ 3 = “ElfChnk”
		$str _ 4 = “-Dr Dump all logs from a channel or .evtx file (raw”
	condition:
		all of them
}

rule Hacktool {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho hacktool”
	strings:
		$str _ 1 = “\\\\.\\pipe\\winsession” wide
		$str _ 2 = “WsiSvc” wide
		$str _ 3 = “ConnectNamedPipe”
		$str _ 4 = “CreateNamedPipeW”
		$str _ 5 = “CreateProcessAsUserW”
	condition:
		all of them
}

rule Multipurpose {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho Multipurpose hacktool”
	strings:
		$str _ 1 = “dump %d|%d|%d|%d|%d|%d|%s|%d”
		$str _ 2 = “kerberos%d.dll”
		$str _ 3 = “\\\\.\\pipe\\lsassp”
		$str _ 4 = “pth <PID:USER:DOMAIN:NTLM>: change”
	condition:
		all of them
}

rule Securetunnel {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho Securetunnel hacktool”
	strings:
		$str _ 1 = “KRB5CCNAME”
		$str _ 2 = “SSH _ AUTH _ SOCK”
		$str _ 3 = “f:l:u:cehR”
		$str _ 4 = “.o+=*BOX@%&#/^SE”
	condition:
		all of them
}

rule Proxy {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho proxy hacktool”
	strings:
		$str _ 1 = “-u user : proxy username”
		$str _ 2 = “--pleh : displays help”
		$str _ 3 = “-x ip/host : proxy ip or host”
		$str _ 4 = “-m : bypass mutex check”
	condition:
		all of them
}

rule jiripbot _ ascii _ str _ decrypt {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho Jiripbot hacktool”
	strings:
		$decrypt _ func = {
			85 FF
			75 03
			33 C0
			C3
			8B C7
			8D 50 01
			8A 08
			40
			84 C9
			75 F9
			2B C2
			53
			8B D8
			80 7C 3B FF ??
			75 3E
			83 3D ?? ?? ?? ?? 00
			56
			BE ?? ?? ?? ??
			75 11
			56
			FF 15 ?? ?? ?? ??
			C7 05 ?? ?? ?? ?? 01 00 00 00
			56
			FF 15 ?? ?? ?? ??
			33 C0
			85 DB
			74 09
			80 34 38 ??
			40
			3B C3
			72 F7
			56
			FF 15 ?? ?? ?? ??
			5E
			8B C7
			5B
			C3
}
	condition:
		$decrypt _ func
}

rule jiripbot _ unicode _ str _ decrypt {
	meta:
		author = “Symantec Security Response”
		date = “2015-07-01”
		description = “Morpho Jiripbot Unicode hacktool”
	strings:
		$decrypt = {
			85 ??
			75 03
			33 C0
			C3
			8B ??
			8D 50 02
			66 8B 08
			83 C0 02
			66 85 C9
			75 F5
			2B C2
			D1 F8
			57
			8B F8
			B8 ?? ?? ?? ??
			66 39 44 7E FE
			75 43
			83 3D ?? ?? ?? ?? 00
			53
			BB ?? ?? ?? ??
			75 11
			53
			FF 15 ?? ?? ?? ??
			C7 05 ?? ?? ?? ?? 01 00 00 00
			53
			FF 15 ?? ?? ?? ??
			33 C0
			85 FF
			74 0E
			B9 ?? 00 00 00
			66 31 0C 46
			40
			3B C7
			72 F2
			53
			FF 15 ?? ?? ?? ??
			5B
			8B C6
			5F
			C3
		}
	condition:
		$decrypt
}