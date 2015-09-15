rule mz_executable // from YARA user's manual
{
meta:
		author = "@iocbucket"
condition:
// MZ signature at offset 0 and ...
uint16(0) == 0x5A4D and
// ... PE signature at offset stored in MZ header at 0x3C
uint32(uint32(0x3C)) == 0x00004550
}

rule is_dll
{
condition:
uint16(0) == 0x5A4D and
uint8(uint32(0x3c)+23) == 0x21
}