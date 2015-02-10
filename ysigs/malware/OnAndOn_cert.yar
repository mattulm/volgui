rule APT_OnAndOn_cert {
	meta:
		author = "ThreatConnect Intelligence Research Team"
		example = "72D72DC1BBA4C5EBC3D6E02F7B446114A3C58EAB"
		license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
		tlp = "AMBER"
	strings:
		$cert = {1F F7 D8 64 18 1C 55 5E 70 CF DD 3A 59 34 C4 7D}
	condition:
		$cert
}