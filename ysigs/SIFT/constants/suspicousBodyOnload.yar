rule SuspicousBodyOnload {
	meta:
		impact = 6
		hide = true
	strings:
		$body = /<body [^>]*onload\s*=\s*['"]*[a-z0-9]+\(['"][a-f0-9]{300}/
	condition:
		1 of them
}