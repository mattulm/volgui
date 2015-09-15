rule moudoor_dropper {
	meta:
		copyright = "Symantec Corporation"

	strings:
		$a = "vptray.exe\x00"
		$b = /cmd.exe \/c ping localhost -n . & del \"%s\"\x00/
		$c1 = "up.bak\x00"
		$c2 = "auto.dat\x00"
		$d = /Symantec.{0,4}Update\x00/
		$e1 = { 0F BE 11 83 F2 ?? 8B 45 ?? 03 45 ?? 88 10 }
		$e2 = { 8A 1C 01 80 F3 ?? 88 1C 01 }
		$e3 = { 80 34 01 ?? 41 3B CA }
		$f = /\x00esourceA[\x00]{1,5}FindR\x00/

	condition:
		4 of them
}

rule moudoor {
	meta:
		copyright = "Symantec Corporation"

	strings:
		$a = "%s%s:%d%s\x00"
		$b = "\x00killme\x00"
		$c = "connected: %s:%d\x00"
		$d = "Global\\X %d" wide
		$e = "360tray.exe\x00" wide
		$f = "delloader\x00"
		$g = "%-24s %-15s 0x%x(%d)" wide

	condition:
		4 of them
}

rule moudoor_downloader {
	meta:
		copyright = "Symantec Corporation"

	strings:
		$a = /GetCompu\x00.{5,14}\x00terNameA\x00/
		$b = /GetVe\x00.{5,14}\x00rsionExA\x00/
		$c = /URLDow\x00.{5,14}\x00nloadToFileA\x00/
		$d = /GetTemp\x00.{5,14}\x00PathA\x00/
		$e = /Creat\x00.{5,14}\x00eMutexA\x00/
		$f = /WinE\x00.{5,14}\x00xec\x00/

	condition:
		3 of them
}

//
// EOF