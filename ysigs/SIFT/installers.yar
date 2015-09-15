rule NSIS : packer
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="NSIS Packer"

	strings:
		$str1="nsis.sf.net"
		
	condition:
		$str1
}

rule WiseInstaller : packer
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="Wise Packer"

	strings:
		$str1="Initializing Wise Installation Wizard"
		
	condition:
		$str1
}


rule InstallShield : packer
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="InstallShield Packer"

	strings:
		$str1="InstallShield"
		
	condition:
		$str1
}

rule InnoSetup : packer
{
	meta:
		author="Andy Browne"
		date_create="30/07/2014"
		description="Inno SetupPacker"

	strings:
		$str1="This installation was built with Inno Setup"
		
	condition:
		$str1
}

