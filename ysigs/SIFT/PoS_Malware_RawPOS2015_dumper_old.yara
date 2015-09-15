rule PoS_Malware_RawPOS2015_dumper_old : RawPOS2015_dumper_old
{
meta:
 author = "Trend Micro, Inc."
 date = "2015-03-10"
 description = "Used to detect RawPOS memory dumper, pre-2012"
 sample_filetype = "exe"
strings:
 $string0 = " Full private dump of all running processes"
 $string1 = " show info on Process like Path"
 $string2 = " Show this help"
 $string3 = " List all running processes"
 $string4 = "Dumping private memory for pid %s to %s.dmp..."
 $string5 = "%s-%d.dmp"
 $string6 = "memdump\\%s-%d.dmp"
 $string7 = "del memdump\\"
 $string8 = "Process Memory Dumper"
 $string9 = "Base size: %u"
 $string10 = "Module ID: %u"
 $string11 = "Hex: %xh"
condition:
 all of ($string*)
}