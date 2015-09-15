rule Winnti_Dropper {
	meta:
		copyright = “Novetta Solutions”
		author = “Novetta Advanced Research Group”
	strings:
		$runner = “%s\\rundll32.exe \”%s\”, DlgProc %s”
		$inflate = “Copyright 1995-2005 Mark Adler”
	condition:
		$runner and $inflate
}

rule Winnti_service {
	meta:
		copyright = “Novetta Solutions”
		author = “Novetta Advanced Research Group”
	strings:
		$newmem = “new memory failed!”
		$value = “can not find value %d\n”
		$onevalue = “find one value %d\n”
		$nofile = “Can not open the file (error %d)”
	condition:
		3 of ($newmem, $value, $onevalue, $nofile)
}

rule Winnti_engine {
	meta:
		copyright = “Novetta Solutions”
		author = “Novetta Advanced Research Group”
	strings:
		$api1 = “SHCreateItemFromParsingName” $datfile = “otfkty.dat”
		$workstart = “work_start”
		$workend = “work_end”
	condition:
		($api1 or $datfile) and ($workstart and $workend)
}

rule Winnti_worker {
	meta:
		copyright = “Novetta Solutions”
		author = “Novetta Advanced Research Group”
	strings:
		$pango = “pango-basic-win32.dll”
		$tango = “tango.dll”
		$dat = “%s\\%d%d.dat”
		$cryptobase = “%s\\sysprep\\cryptbase.dll”
	condition:
		$pango and $tango and $dat and $cryptobase
}