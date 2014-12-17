rule embedded_macho
{
    meta:
        author = "nex"
        description = "Contains an embedded Mach-O file"

    strings:
        $magic1 = { ca fe ba be }
        $magic2 = { ce fa ed fe }
        $magic3 = { fe ed fa ce }
    condition:
        any of ($magic*) and not ($magic1 at 0) and not ($magic2 at 0) and not ($magic3 at 0)
}

rule embedded_pe
{
    meta:
        author = "nex"
        description = "Contains an embedded PE32 file"

    strings:
        $a = "PE32"
        $b = "This program"
        $mz = { 4d 5a }
    condition:
        ($a or $b) and not ($mz at 0)
}

rule embedded_win_api
{
    meta:
        author = "nex"
        description = "A non-Windows executable contains win32 API functions names"

    strings:
        $mz = { 4d 5a }
        $api1 = "CreateFileA"
        $api2 = "GetProcAddress"
        $api3 = "LoadLibraryA"
        $api4 = "WinExec"
        $api5 = "GetSystemDirectoryA"
        $api6 = "WriteFile"
        $api7 = "ShellExecute"
        $api8 = "GetWindowsDirectory"
        $api9 = "URLDownloadToFile"
        $api10 = "IsBadReadPtr"
        $api11 = "IsBadWritePtr"
        $api12 = "SetFilePointer"
        $api13 = "GetTempPath"
        $api14 = "GetWindowsDirectory"
    condition:
        not ($mz at 0) and any of ($api*)
}

rule exe_drop {
	strings:
		$a  = "This program cannot be run in DOS mode"
	condition:
		all of them
}

rule is_pe
{
    condition:
        // MZ signature at offset 0 and ...
        uint16(0) == 0x5A4D and 
        // ... PE signature at offset stored in MZ header at 0x3C
        uint32(uint32(0x3C)) == 0x00004550
}

