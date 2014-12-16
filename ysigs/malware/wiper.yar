rule unknown_wiper_str {
	strings:
		$STR1 = "#99E2428CCA4309C68AAF8C616EF3306582A64513E55C786A864BC83DAFE0C78585B692047273B0E55275102C66" fullword nocase
		$MZ = "MZ"
	condition:
		$MZ at 0 and $STR1
}

rule unknown_wiper_IPs {
	strings:
		$IP1 = "203.131.222.102" fullword nocase
		$IP2 = "217.96.33.164" fullword nocase
		$IP3 = "88.53.215.64" fullword nocase
		$MZ = "MZ"
	condition:
		$MZ at 0 and all of them
}

rule unknown_wiper_error_strings {
	strings:
		$ERR1 = "$MFT Record read failed." fullword nocase
		$ERR2 = "Drive Boot Sector read failed." fullword nocase
		$ERR3 = "SetFilePointer failed." fullword nocase
		$MZ = "MZ"
	condition:
		$MZ at 0 and all of them
}

//
// EOF