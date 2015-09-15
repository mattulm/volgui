rule APT_RedOctober_CloudAtlas_ctfmonrn
{
meta:
	author = "ThreatConnect Intelligence Research Team - Wes Hurd"
	example = "4BA012C1D6DBD9382933E12C79D483A9"
	license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
	tlp = "AMBER"
strings:
	$ = "ctfmonrn.dll" wide ascii
	$ = "st = regsvr+Chr(34)+t+Chr(34)"
condition:
	any of them
}