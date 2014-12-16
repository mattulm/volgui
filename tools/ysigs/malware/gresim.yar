rule gresim
{
	meta:
		copyright = "Symantec Corporation"

	strings:
		$a1 = "\x00http://%s/imgres?q="
		$a2 = "\x00http://%s/search?q=Google&go=&qs=n&form="
		$a3 = "http://0.0.0.0/1\x00"
		$a4 = "[IISEND=0x%08X][Recv:]"
		$a5 = /IISCMD Error:%d[\x0A]?\x00/
	condition:
		2 of them
}