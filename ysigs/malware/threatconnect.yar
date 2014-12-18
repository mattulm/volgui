rule APT_Elise
{
meta:
	author = "ThreatConnect Intelligence Research Team - Wes Hurd"
	license = "Usage of this signature is subject to the ThreatConnect Terms of Service, which are incorporated herein by reference."
	tlp = "AMBER"
strings:
	$0E = "\\000ELISEA"
	$D = "~DF37382D8F2E.tmp" nocase wide ascii
	$SE = "SetElise.pdb" wide ascii
	$xpage = "/%x/page_%02d%02d%02d%02d.html" wide ascii
condition:
	any of them
}

rule Tranchulas_C2 { 
	meta: 
		author = "ThreatConnect Intel Research Team - Wes Hurd" 
	strings: 
		$ip = "199.91.173." 
		$mv = "masalavideos." 
		$wu = "windowsupdate.no-ip.biz" 
		
	condition: 
		any of them 
}

rule Tranchulas_Gen_Callback { 
	meta: 
		author = "ThreatConnect Intel Research Team - Wes Hurd" 
		
	strings: 
		$f = "fetch_updates_8765" 
		$i = "is_array.php" 
		$php_gen = ".php?compname=" 
		
	condition: 
		any of them 
}  

rule Tranchulas_Gen_Debug { 
	meta: 
		author = "ThreatConnect Intel Research Team - Wes Hurd" 
	
	strings: 
		$ca = "C:\\Users\\Cath\\" 
		$ce = "Cert-India" 
		$tr = "Tranchulas" 
		$um = "umairaziz27" nocase 
		
	condition: 
		any of them 
}  

rule Tranchulas_Gen_DLL_Down { 
	meta: 
		author = "ThreatConnect Intel Research Team - Wes Hurd" 
		
	strings: 
		$1 = "/update_dll.dll" 
		
	condition: 
		any of them 
}  

rule Tranchulas_Gen_Loader { 
	meta: 
		author = "ThreatConnect Intel Research Team - Wes Hurd" 
		
	strings: 
		$1 = "@microsoft@windefender.exe" 
		
	condition: 
		any of them 
}

rule APT_ZXShell_VFW
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$D = "DoActionRDSRV" wide ascii
	$h = "h:\\Prj2012" nocase wide ascii
	$R = "ReleaseTest\\Remote" nocase wide ascii
	$R1 = "RemoteDeskTop.dll" wide ascii
	$z = "zxapp-console\\" nocase wide ascii
condition:
	any of them
}

rule ZXProxy
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	
strings:
	$C = "\\Control\\zxplug" nocase wide ascii
	$h = "http://www.facebook.com/comment/update.exe" wide ascii
	$S = "Shared a shell to %s:%s Successfully" nocase wide ascii
condition:
	any of them
}

rule APT_Hikit_msrv
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$m = {6D 73 72 76 2E 64 6C 6C 00 44 6C 6C}
condition:
	any of them
}

rule APT_Derusbi_Gen
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$2 = "273ce6-b29f-90d618c0" wide ascii
	$A = "Ace123dx" fullword wide ascii
	$A1 = "Ace123dxl!" fullword wide ascii
	$A2 = "Ace123dx!@#x" fullword wide ascii
	$C = "/Catelog/login1.asp" wide ascii
	$DF = "~DFTMP$$$$$.1" wide ascii
	$G = "GET /Query.asp?loginid=" wide ascii
	$L = "LoadConfigFromReg failded" wide ascii
	$L1 = "LoadConfigFromBuildin success" wide ascii
	$ph = "/photoe/photo.asp HTTP" wide ascii
	$PO = "POST /photos/photo.asp" wide ascii
	$PC = "PCC_IDENT" wide ascii
condition:
	any of them
}

rule APT_Derusbi_DeepPanda
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	reference = "http://www.crowdstrike.com/sites/default/files/AdversaryIntelligenceReport_DeepPanda_0.pdf"
strings:
	$D = "Dom4!nUserP4ss" wide ascii
condition:
	$D
}

rule APT_DeputyDog_Fexel
{
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

rule APT_RedOctober_CloudAtlas_ctfmonrn {
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