rule InceptionDLL
{
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a = "dll.polymorphed.dll"
		$b = { 83 7d 08 00 0f 84 cf 00 00 00 83 7d 0c 00 0f 84 c5 00
			   00 00 83 7d 10 00 0f 84 bb 00 00 00 83 7d 14 08 0f 82 
			   b1 00 00 00 c7 45 fc 00 00 00 00 8b 45 10 89 45 dc 68 
			   00 00 }
		$c = { FF 15 ?? ?? ?? ?? 8b 4d 08 8b 11 c7 42 14 00 00 00 00
			   8b 45 08 8b 08 8b 55 14 89 51 18 8b 45 08 8b 08 8b 55 
			   0c 89 51 1c 8b 45 08 8b 08 8b 55 10 89 51 20 8b 45 08 
			   8b 08 }
		$d = { 68 10 27 00 00 FF 15 ?? ?? ?? ?? 83 7d CC 0a 0f 8d 47
			   01 00 00 83 7d d0 00 0f 85 3d 01 00 00 6a 20 6a 00 8d 
			   4d d4 51 e8 ?? ?? ?? ?? 83 c4 0c 8b 55 08 89 55 e8 c7 
			   45 d8 }
		$e = { 55 8b ec 8b 45 08 8b 88 ac 23 03 00 51 8b 55 0c 52 8b
			   45 0c 8b 48 04 ff d1 83 c4 08 8b 55 08 8b 82 14 bb 03 
			   00 50 8b 4d 0c 51 8b 55 0c 8b 42 04 }
	condition:
		any of them
}

rule InceptionRTF {
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a = "}}PT@T"
		$b = "XMLVERSION \"3.1.11.5604.5606"
		$c = "objclass Word.Document.12}\\objw9355" 
	condition:
		all of them
}

rule InceptionMips {
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a = "start_sockat" ascii wide
		$b = "start_sockss" ascii wide
		$c = "13CStatusServer" ascii wide
	condition:
		all of them
}

rule InceptionVBS {
	meta: 
		author = "Blue Coat Systems, Inc; modified by Florian Roth"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a = "c = Crypt(c,k)"
		$b = "fso.BuildPath( WshShell.ExpandEnvironmentStrings(a)"
		$c = "Dim p(4)" fullword ascii
	condition:
		all of them
}

rule InceptionBlackberry {
	meta: 
		author = "Blue Coat Systems, Inc; modified by Florian Roth"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a1 = "POSTALCODE:"
		$a2 = "SecurityCategory:"
		$a3 = "amount of free flash:"
		$a4 = { 24 d8 37 31 7c 27 31 27 7c 3a } /* replaced non ascii character srtring $Ø71|'1'|: */
		$b1 = "God_Save_The_Queen"
		$b2 = "UrlBlog"
	condition:
		all of ($a*) or all of ($b*)
}

rule InceptionAndroid {
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a1 = "BLOGS AVAILABLE="
		$a2 = "blog-index"
		$a3 = "Cant create dex="
	condition:
		all of them
}

rule InceptionIOS {
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a1 = "Developer/iOS/JohnClerk/"
		$b1 = "SkypeUpdate"
		$b2 = "/Syscat/"
		$b3 = "WhatsAppUpdate"
	condition:
		$a1 and any of ($b*)
}

rule InceptionCloudMe {
	meta: 
		author = "Florian Roth"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		score = 65
		description = "Compromised CloudMe accounts from BlueCoat operation Inception"
	strings:
		$s1 = "franko7046" fullword
		$s2 = "sanmorinostar" fullword
		$s3 = "tem5842" fullword
		$s4 = "bimm4276" fullword
		$s5 = "carter0648" fullword
		$s6 = "depp3353" fullword
		$s7 = "frogs6352" fullword
		$s8 = "daw0996" fullword
		$s9 = "chak2488" fullword
		$s10 = "corn6814" fullword	
		$s11 = "james9611" fullword
		$s12 = "lisa.walker" fullword
		$s13 = "billder1405" fullword
		$s14 = "droll5587" fullword
		$s15 = "samantha2064" fullword
		$s16 = "chloe7400" fullword
		$s17 = "browner8674935" fullword
		$s18 = "parker2339915" fullword
		$s19 = "young0498814" fullword
		$s20 = "hurris4124867" fullword
		$x1 = "cloudme" nocase fullword
	condition:
		1 of ($s*) and $x1
}