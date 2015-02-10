rule powerliks_rundll32_exe_javascript {
	meta:
		author: Didier Stevens
	strings:
		$a = "rundll32.exe" nocase
		$b = "javascript" nocase
	condition:
		$a and $b
|