rule ShopAtHome : PUP
{
    strings:
        $a1= "ShopAtHome"

    
    condition:
		$a1   
}

rule RivalGaming : PUP
{
	strings:
		$a1 = "rivalgaming"


	condition:
		$a1
}

rule Possible_DomaIQ : PUP
{
	strings:
		$a1 = "1438D407-A621-41B3-87B7-B1028DA635DF"
	
	
	condition:
		$a1
}

rule SuperbApp : PUP
{
	strings:
		$a1 = "SuperbApp"
	
	
	condition:
		$a1
}

rule WinTools : PUP
{
	strings:
		$a1 = "WinTools"
	
	
	condition:
		$a1
}

rule PlusHD81 : PUP
{
	strings:
		$a1 = "Plus-HD-8.1"
	
	
	condition:
		$a1
}

rule StarApp : PUP
{
	strings:
		$a1 = "StarApp"
	
	
	condition:
		$a1
}

rule SoftSafe : PUP
{
	strings:
		$a1 = "SoftSafe"
	
	
	condition:
		$a1
}

rule CompanyCloudSoft : PUP
{
	strings:
		$a1 = "CloudSoft"
	
	
	condition:
		$a1
}

rule CompanyClickIT : PUP
{
	strings:
		$a1 = "ClickIT"
	
	
	condition:
		$a1
}

rule IirDeremder : PUP
{
	strings:
		$a1 = "IirDeremder"
	
	
	condition:
		$a1
}

rule PinballCorporation : PUP
{
    strings:
        $a1= "Pinball Corporation."

    
    condition:
		$a1  
}

rule Zango : PUP
{
    strings:
        $a1= "Zango"

    
    condition:
		$a1  
}

rule Hotbar : PUP
{
    strings:
        $a1= "HOTBAR.COM Inc."
    
    condition:
		$a1
}

rule Conduit : PUP
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="Conduit file"

	strings:
		$str1 = "Conduit Ltd"
		$str2 = "conduit.com"
		$str3 = "CONDUITENGINEEMBBED.EXE"
		
	condition:
		$str1 or $str2 or $str3
}

rule Yontoo : PUP
{
    strings:
        $a1= "Yontoo"

    
    condition:
		$a1   
}

rule DealPly : PUP
{
    strings:
        $a1= "DealPly"

    
    condition:
		$a1   
}


rule Seekmo : PUP
{
    strings:
        $a1= "Seekmo"

    
    condition:
		$a1   
}


rule WhenU : PUP
{
    strings:
        $a1= "WHENU.COM INC"

    
    condition:
		$a1   
}



rule WebCake : PUP
{
    strings:
        $a1= "Web Cake"

    
    condition:
		$a1   
}

rule OpenCandy : bundler
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="OpenCandy bundler"

	strings:
		$str1="OpenCandy"
		
	condition:
		$str1
}

rule Spigot : PUP
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="OpenCandy bundler"

	strings:
		$str1="Spigot"
		
	condition:
		$str1
}

rule Ask : PUP
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="Ask files"

	strings:
		$str1="Ask.com"
		
	condition:
		$str1
}



rule Mindspark : PUP
{
	meta:
		author="Andy Browne"
		date_create="24/07/2014"
		description="Mindspark files"

	strings:
		$str1="Mindspark"
		
	condition:
		$str1
}


rule Goobzo : PUP
{
	meta:
		author="Andy Browne"
		date_create="29/08/2014"
		
	strings:
		$str1="Goobzo"
		
	condition:
		$str1
}
