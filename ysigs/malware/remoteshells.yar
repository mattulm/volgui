// Remote Shells

rule beep_remote_shell
{
	meta:
	author = "@patrickrolsen"
	reference = "0625b5b010a1acb92f02338b8e61bb34"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$mz = { 4d 5a }
	$s1 = "%s\\admin$\\system32\\%s"
	$s2 = "BeepService"
	$s3 = "In ControlService"
	$s4 = "In OpenScManager"
	$s5 = "In CreateService"
	$s6 = "Service is RUNNING"
	$s7 = "Service is not running"
	$s8 = "In DeleteService"
	$s9 = "Remove the service OK"
condition:
	($mz at 0) and (all of ($s*))
}

rule wp_shell_crew
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$mz = { 4d 5a } // MZ
	$s1 = "IsWow64Process"
	$s2 = "svchost.exe -k netsvcs"
	$s3 = "Services\\%s\\Parameters"
	$s4 = "%s %s %s"
	$s5 = "-%s-%03d"
	$s6 = "127.0.0.1"
	$s7 = "\\temp\\" fullword
condition:
	($mz at 0) and (all of ($s*))
}