rule Neverquest1
{
	meta:
	
		Author = "Marcus Ruffin"
		maltype = "crime"
		date = "2014-01"
		version = "v1.0"
			      
	strings:
	
		$network_1 = "/forumdisplay.php?fid="
    		$network_2 = "/post.aspx?forumID="
		$network_3 = "/post.aspx?messageID="
		$string1 = "././@LongLink"
		$string2 = "[BC] Cmd need disconnect"
		$string3 = "[BC] Wait Ping error %u[%u]"
		$string4 = "PID: %u [%0.2u:%0.2u:%0.2u]"
		$string5 = "ustar"
		$string6 = "NoProtectedModeBanner"
	
	condition:
	
		all of them
			      
            }
