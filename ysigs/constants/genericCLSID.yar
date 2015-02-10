rule DecodedGenericCLSID : decodedOnly
{
	meta:
		impact = 0
	strings:
		$gen = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/ nocase
	condition:
		1 of them
}