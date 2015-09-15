rule fexel2 {
	meta:
		copyright = "Symantec Corporation"

	strings:
		$s1 = "%cUpload failed! [Remote error code: %d]" wide
		$s2 = "Can't open shell!"                        wide
		$s3 = "DGGYDSYRL\x00"
		$s3w = "DGGYDSYRL" wide
		$s4 = "%c%c%c.exe /c del \"%s\"\x00"
	condition:
		(2 of ($s1,$s2,$s3,$s3w,$s4)) and uint16(0)==0x5A4D and uint32(uint32(0x3c))==0x00004550 and uint32(uint32(0x3c)+0x28)!=0
}


rule APT_DeputyDog_Fexel {
	meta:
		author = "ThreatConnect Intelligence Research Team"
	
	strings:
		$180 = "180.150.228.102" wide ascii
		$0808cmd = {25 30 38 78 30 38 78 00 5C 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 [2-6] 43 00 61 00 6E 00 27 00 74 00 20 00 6F 00 70 00 65 00 6E 00 20 00 73 00 68 00 65 00 6C 00 6C 00 21}
		$cUp = "Upload failed! [Remote error code:" nocase wide ascii
		$DGGYDSYRL = {00 44 47 47 59 44 53 59 52 4C 00}
		$GDGSYDLYR = "GDGSYDLYR_%" wide ascii

	condition:
		any of them
}