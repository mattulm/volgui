rule ObfuscationPattern { 

	meta:
		impact = 0
	
	strings:
		$eval = "eval" nocase fullword
		$charcode = "String.fromCharCode" nocase fullword
		$loc = "location" nocase fullword
		$deanEdwards = "function(p,a,c,k,e,d)" nocase
	
	condition:
		2 of them
}