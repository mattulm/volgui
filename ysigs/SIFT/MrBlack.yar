rule MrBlack  
    meta:
        description = "MrBlack Malware Family"
        author = "Brian Warehime"
        date = "2015-06-12"
{
    strings:
        $attack_string1 = "9CAttackIe"
        $attack_string2 = "9CAttackCc"
        $attack_string3 = "10CTcpAttack"
        $attack_string4 = "15CAttackCompress"
        $attack_string5 = "10CAttackPrx"
        $attack_string6 = "10CAttackAmp"
        $attack_string7 = "10CAttackDns"
        $attack_string8 = "11CAttackIcmp"
        $attack_string9 = "10CAttackSyn"
        $attack_string10 = "10CAttackUdp"
        $attack_string11 = "13CPacketAttack"
        $attack_string12 = "11CAttackBase"
        $attack_string13 = "7CSerial"
        $user_agent1 = "Mozilla/5.0 (|S|) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/|D&23&25|.|D&0&9|.|D&1000&9000|.|D&10&99| Safari/537.17"
        $user_agent2 = "Mozilla/5.0 (|S|; rv:18.0) Gecko/20100101 Firefox/18.0"
        $user_agent3 = "Opera/|D&7&9|.|D&70&90| (|S|) Presto/2.|D&8&18|.|D&90&890| Version/|D&11&12|.|D&10&19|"
    condition:
         all of them
		 