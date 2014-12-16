rule naid_dropper {
	meta:
		copyright = "Symantec Corporation"
	strings:
		$a1 = "/c del \"\x00\x00\" > nul" wide
		$a2 = "\" > nul\x00/c del \"\x00" wide
		$b = "rundll32.exe \"%s\", Launch\x00" wide
		$c = "%%USERPROFILE%%\\%s.dll\x00" wide
	condition:
		($a1 or $a2) and $b and $c
}

rule naid_dll {
	meta:
		copyright = "Symantec Corporation"
	strings:
		$a = "rat_UnInstall\x00" wide nocase
		$b = "McpRoXy.exe\x00" wide nocase
		$c = "%s\\%d.bak\x00" wide
		$d = "rundll32.exe \"%s\", Launch\x00" wide
	condition:
		2 of them
}

rule naid_dll_unpacked {
	meta:
		copyright = "Symantec Corporation"
	strings:
		$a = "%TEMP%\\%s.ax\x00" wide
		$b = "CONNECT %ls:%d HTTP/1.1\x0d\x0a"
		$c = "POST http://%ls:%d/%x HTTP/1.1\x0d\x0a"
		$d = "%%TEMP%%\\%s_p.ax\x00" wide
		$e = "Dog create a loop thread\x0a\x00"
    condition:
        3 of them
}