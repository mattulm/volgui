rule CrowdStrike_PutterPanda_01 : fourh_stack_strings putterpanda
	{
	meta:
		description = "PUTTER PANDA - 4H RAT"
                author = "CrowdStrike"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
		yara_version = ">=1.6"
	
	strings:
	    $key_combined_1 = { C6 44 24 ?? 34 C6 44 24 ?? 36 C6 44 24 ?? 21 C6 44 24 ?? 79 C6 44 24 ?? 6F C6 44 24 ?? 00 }
	
	
	    // ebp
	    $keyfrag_ebp_1 = { C6 45 ?? 6C }    // ld66!yo
	    $keyfrag_ebp_2 = { C6 45 ?? 64 } 
	    $keyfrag_ebp_3 = { C6 45 ?? 34 }
	    $keyfrag_ebp_4 = { C6 45 ?? 36 }
	    $keyfrag_ebp_5 = { C6 45 ?? 21 }
	    $keyfrag_ebp_6 = { C6 45 ?? 79 }
	    $keyfrag_ebp_7 = { C6 45 ?? 6F }
	
	    // esp
	    $keyfrag_esp_1 = { c6 44 ?? 6C }    // ld66!yo
	    $keyfrag_esp_2 = { c6 44 ?? 64 }
	    $keyfrag_esp_3 = { c6 44 ?? 34 }
	    $keyfrag_esp_4 = { c6 44 ?? 36 }
	    $keyfrag_esp_5 = { c6 44 ?? 21 }
	    $keyfrag_esp_6 = { c6 44 ?? 79 }
	    $keyfrag_esp_7 = { c6 44 ?? 6F }
	
	    // reduce FPs by checking for some common strings
	    $check_zeroes = "0000000"
	    $check_param = "Invalid parameter"
	    $check_ercv = "ercv= %d"
	    $check_unk = "unknown"
	
	condition:
	    any of ($key_combined*) or 
	    (1 of ($check_*) and
	        (
	            (
	                all of ($keyfrag_ebp_*) and
	                for any i in (1..#keyfrag_ebp_5) : (
	                    for all of ($keyfrag_ebp_*): ($ in (@keyfrag_ebp_5[i]-100..@keyfrag_ebp_5[i]+100))
	                )
	            )
	            or
	            (
	                for any i in (1..#keyfrag_esp_5) : (
	                    for all of ($keyfrag_esp_*): ($ in (@keyfrag_esp_5[i]-100..@keyfrag_esp_5[i]+100))
	                )
	            )
	        )
	    )
	}
	
	
rule CrowdStrike_ PutterPanda _02 : rc4_dropper putterpanda
	{
	meta:
		description = "PUTTER PANDA - RC4 dropper"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $res_lock = "LockResource"
	    $res_size = "SizeofResource"
	    $res_load = "LoadResource"
	
	    $com = "COMSPEC"
	
	    $stack_h = { C6 4? [1-2] 68 }    
	    $stack_o = { C6 4? [1-2] 6F }
	    $stack_v = { C6 4? [1-2] 76 }
	    $stack_c = { C6 4? [1-2] 63 }
	    $stack_x = { C6 4? [1-2] 78 }
	    $stack_dot = { C6 4? [1-2] 2E }
	
	    $cryptaq = "CryptAcquireContextA"
	
	condition:
	    uint16(0) == 0x5A4D and
	    (all of ($res_*)) and 
	    (all of ($stack_*)) and
	    $cryptaq and $com
	}
	
	
rule CrowdStrike_ PutterPanda _03 : threepara_para_implant putterpanda
	{
	meta:
		description = "PUTTER PANDA - 3PARA RAT"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $parafmt        = "%s%dpara1=%dpara2=%dpara3=%d"
	    $class_attribe  = "CCommandAttribe"
	    $class_cd       = "CCommandCD"
	    $class_cmd      = "CCommandCMD"
	    $class_nop      = "CCommandNop"
	
	condition:
	    $parafmt or all of ($class_*)
	}
	
	rule CrowdStrike_ PutterPanda _04: pngdowner putterpanda
	{
	meta:
		description = "PUTTER PANDA - PNGDOWNER"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $myagent = "myAgent"
	    $readfile = "read file error:"
	    $downfile = "down file success"
	    $avail = "Avaliable data:%u bytes"
	
	condition:
	    3 of them
	}
	
rule CrowdStrike_ PutterPanda _05 : httpclient putterpanda
	{
	meta:
		description = "PUTTER PANDA - HTTPCLIENT"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $recv_wrong = "Error:recv worng"
	
	condition:
	    any of them
	}
	
rule CrowdStrike_ PutterPanda _06 : xor_dropper putterpanda
	{
	meta:
		description = "PUTTER PANDA - XOR based dropper"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $xorloop = { 8b d0 83 e2 0f 8a 54 14 04 30 14 01 83 c0 01 3b c6 7c ed  }
	
	condition:
	    $xorloop
	}


#
#  Putter Panda Snort Rules
#
#

	
alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg: "CrowdStrike PUTTER PANDA 4H Beacon Message"; \
  content: "/search5"; http_uri; \
  content: "?h1="; http_uri; \
  content: "&h2="; http_uri; \
  content: "&h3="; http_uri; \
  content: "&h4="; http_uri; \
  classtype:trojan-activity; metadata: service http; \
  sid: 171200702; rev: 20120424;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER_PANDA 3PARA RAT initial beacon - URI"; \
  flow:to_server, established; \
  content:"/microsoft/errorpost/default/connect.aspx?ID="; http_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 181311501; rev: 20131212;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA 3PARA RAT initial beacon - Hashed bytes"; \
  flow:to_server, established; \
  content:"| c4 65 f1 b3 cf a5 7e e2 c0 1a d4 7f 78 46 26 b5 86 15 f9 34 9c 3d 67 84 6a 48 aa df dc 30 60 24 |"; depth: 2000;\
  classtype: trojan-activity; \
  sid: 181311502; rev: 20131212;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA 3PARA RAT data exfiltration";\
  flow:to_server, established; \
  content:"POST"; http_method; \
  content:"/microsoft/errorpost/default.aspx?ID="; http_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 181311503; rev: 20131212;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA 3PARA RAT tasking request";\
  flow:to_server, established; \
  content:"GET"; http_method; \
  content:".aspx?ID="; http_raw_uri; \
  content: "para1="; http_raw_uri; within: 15\
  content: "para2="; http_raw_uri; within: 20; \
  content: "para3="; http_raw_uri; within: 20; \
  classtype: trojan-activity; metadata: service http; \
  sid: 181311504; rev: 20140421;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA PNGDOWNER user agent"; \
  flow:to_server, established; \
  content: "User-Agent: myAgent"; http_header; \
  classtype: trojan-activity; metadata: service http; \
  sid: 171400101; rev: 20140401;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA HTTPCLIENT Request"; \
  flow:to_server, established; \
  content: "/MicrosoftUpdate/ShellEX/KB"; http_uri; \
  content: "/default.asp?tmp="; within: 35; http_raw_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 171400102; rev: 20140401;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA HTTPCLIENT Request 2"; \
  flow:to_server, established; \
  content: "/Microsoft/errorpost"; http_uri; \
  content: "/default.asp?tmp="; within: 35; http_raw_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 171400103; rev: 20140401;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA HTTPCLIENT Request 3"; \
  flow:to_server, established; \
  content: "/MicrosoftUpdate/GetUpdate/KB"; http_uri; \
  content: "/default.asp?tmp="; within: 35; http_raw_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 171400104; rev: 20140401;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER_PANDA HTTPCLIENT Request 4"; \
  flow:to_server, established; \
  content: "/Microsoft/update"; http_uri; \
  content: "/debug"; http_raw_uri; within: 20; \ 
  content: "/default.asp?tmp="; within: 30; http_raw_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 171400105; rev: 20140401;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA HTTPCLIENT Request 5"; \
  flow:to_server, established; \
  content: "/MicrosoftUpdate/GetFiles/KB"; http_uri; \
  content: "/default.asp?tmp="; within: 35; http_raw_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 1971400106; rev: 20140401;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"CrowdStrike PUTTER PANDA HTTPCLIENT Request 6"; \
  flow:to_server, established; \
  content: "/MicrosoftUpdate/WWRONG/KB"; http_uri; \
  content: "/default.asp?tmp="; within: 35; http_raw_uri; \
  classtype: trojan-activity; metadata: service http; \
  sid: 171400107; rev: 20140401;)


#
# CSV Indicators
#

bc4e9dad71b844dd3233cfbbb96c1bd3,md5_hash
92656d6028310a5be7ef887b094f45c3,md5_hash
035028bbdfaa88fb35cc4d4c65c56e54,md5_hash
198ebc479502b0dc4232b1bf9710385d,md5_hash
e7837e464ef72d0115076ffbbf1cbf23,md5_hash
cfffee14a4b644ba69b247ac8db887ff,md5_hash
5bdd6c6a89a7777b88a04958d308d7a2,md5_hash
a0ce34f68d65848a873bd8e6fa3a7b41,md5_hash
92965138a6a2f64b0290fd46f1fa9c9e,md5_hash
d07257cd8debd5a09edcd7a88b4f4149,md5_hash
6634855afd81405bfa42d49ce3d2dd90,md5_hash
6b638ef5b146aadf7368aef48eb538d7,md5_hash
b74e44550155f97840176b210befaac2,md5_hash
4225ae0be4099a86849d6ae0522ce798,md5_hash
5b8315e92122464e9d9d8258c8db3dd3,md5_hash
b4d42df0af6923ea02763c8a2501540c,md5_hash
5c60fa65cb19f867b34a8e3af0222389,md5_hash
04b6fd7c5e12f4291472cce447d5a3fb,md5_hash
2fc22095eebd5185aff0803b42027760,md5_hash
1fa4b7b8ba7bff7d404cba53f8c6c222,md5_hash
f52a15bac250f393cdaf40b99a590c16,md5_hash
0073194788c491e17460d1ee66f9c1ad,md5_hash
1429beb46f97a6eaf9bbdf0e470f7d57,md5_hash
40ad9ba37ef29ecb9e2183ad45e99d7b,md5_hash
8e8b2b32dd3048b729d32248b5ea939f,md5_hash
b54e91c234ec0e739ce429f47a317313,md5_hash
bdf62f5ed65acd4cda6478120069740f,md5_hash
f10b7c90fcd450baec0396adb4c5ea90,md5_hash
2f1ca6394899b8fb6ac1eb9f1e352c93,md5_hash
b871087f7715e9d1ec3884962ee37067,md5_hash
fea7b99aa54da7cc2d6b925f3beaed2a,md5_hash
6b0b066eb7bd29c3a0f984c8b487e6be,md5_hash
9808e9a4735e81b172b5cb72142b5ec4,md5_hash
6f4c3f3778fa0def410fda7e5d5570dc,md5_hash
063153e5359953a6a3a20b440ddfcf66,md5_hash
c4898f7b43db892e96dda9c06ba9205f,md5_hash
0e0182c9481b007e6564d72c99b05ad8,md5_hash
43e7fb391fe1744965d31b280be2ddc7,md5_hash
4ec7ee0915d0c1cece1ffafd0e72bd76,md5_hash
1c42e07a5f344bb107715f4ce864c452,md5_hash
710143e723eec132df5bf2d11d1b1a97,md5_hash
3fcb85d746313dfddd108720eff6dc82,md5_hash
3f9973cd231b27b7efca490f5a176508,md5_hash
76a5102f8fa1bef7689c0c20e447f28b,md5_hash
6c93ccdd6d3140c2c338f968273ac680,md5_hash
08c7b5501df060ccfc3aa5c8c41b452f,md5_hash
2244ea9c999576928b6833845877a397,md5_hash
22f7b9afde6a21fc275130a41076bfe4,md5_hash
2392d47e7a357d77bcdb260ad9f4695a,md5_hash
057c9978749095d8dfdcfefe2a04d111,md5_hash
1b140bbd037bb909ecb9dcb71b9ce9f4,md5_hash
9ac3b5966f65e21e27c10fd8d2e7152e,md5_hash
67408fbec99d3d06b07b44f25c7ecea5,md5_hash
a97392a796dae335d918cbdf968cfde7,md5_hash
8a35afbfeac65d87448bd37d7d0da072,md5_hash
223b5298db9a871616a0cdc92c90dee8,md5_hash
d427d0192828647541ca04d5ae0d77b7,md5_hash
3b31982141daedda89ceecf4b5790454,md5_hash
e87ef0f156a48902019ff43ae22c6ba9,md5_hash
2726087f3c7f0fb808e1580735b2e964,md5_hash
270508e83b732f250239ffd5961458f9,md5_hash
f29a966426bb91154cece807ee778b70,md5_hash
f5c80092c3d637b5618daf3de1e30be4,md5_hash
fe3cdc4b22d30d07866d79495a38bd19,md5_hash
b7db2fdd3b047639b7a28afc4ff4fbfd,md5_hash
1ee30f7ecaf25af38cf684ca56b75cf2,md5_hash
5ce2dea534c1808a1da8c02946595cc0,md5_hash
304637b2cd1d42d9ffd01d885862e330,md5_hash
872e1e5f826d0bf0ff476ebe6355665f,md5_hash
e3433894a914826773ace894d1fa1d5f,md5_hash
facad2d2063ed4016cd5f38b83c5d439,md5_hash
aa093dac070226f877033480d2a117ad,md5_hash
6ff7acc178eb6ae0f75d2f6f989c468d,md5_hash
2db413f090b694aa6b6ef19ec2b53b1b,md5_hash
68c56b0e50cda3b8d7af72df06e8f0fc,md5_hash
5f652d20c5979d3af1c78e053530c247,md5_hash
c16b7efd603f2ae87ba52511d4e18897,md5_hash
ecef8b506ea561c8ebf6dd99e6adef2a,md5_hash
e57ccb9ce5e455d29b24d69a4b58040e,md5_hash
80618d4d7cafbc04a116409dbb292d13,md5_hash
43e97d338a226c5112d07090309feae8,md5_hash
d7a6f573cb417a3de13f65827ac045b1,md5_hash
dea5c8f4acac0391f5ee7713e76fd043,md5_hash
3eaa365102a0291bbe07da4436d8df42,md5_hash
720e8ce8f8a776c76839417a453d6664,md5_hash
6a1d0e84e780145581dd8be9b221a475,md5_hash
5f51e217da8446f299e3f69cf6afb5b0,md5_hash
8deec3498088078a64b53dc0693ebff9,md5_hash
de05fbe2a51bda0ca1e235f38ca0af5f,md5_hash
3fae873e7a4b96c548c60df211207abe,md5_hash
0e45952c1e7fb40662f9caf13953e4ca,md5_hash
038d64a04937be3873183083bac7a07b,md5_hash
4b92f32e875ccddb09e4eae613e77f0b,md5_hash
997e7566f2c3b1008bc77de791d4aac1,md5_hash
687424f0923df9049cc3a56c685eb9a5,md5_hash
2df62ca63be41ec6fab641f72084424a,md5_hash
3fb4e08bb7e5e9700d99abbe90619fa7,md5_hash
4d87b8c92afc599ccaea7b06be3f4250,md5_hash
9a3b80702f49c6eb8a2354225d4207b1,md5_hash
6dc5d006eafa5e135ec89fa456060b58,md5_hash
2357372b80077d6e5c27cc337a94ca3c,md5_hash
840f6d69893d70547762ef4309024d40,md5_hash
8f8b47eec7e67ea60cc29f3d44266ee3,md5_hash
a585734102640c6a7d3cba4630dd2b55,md5_hash
3133142c7394b2918f01734e574dbfba,md5_hash
bdf512d5eef853d07c0db345345e3db7,md5_hash
289a27727f1b1af8b2e49fd4d987f36b,md5_hash
2f450a095a45a243c618ba05361d8e0c,md5_hash
98eb97d0b709a5b0569201fb84e77c27,md5_hash
64b5f6d1ecfb27bf832848609dff90fe,md5_hash
9d5fdd186eddd3c766ff5ac98c2b27ef,md5_hash
830e19b54647db15b820ab24fab5aa31,md5_hash
a6ba741ab7d904a2fbdfa5fe57256bb1,md5_hash
a17bca94b20bbb84b82eba6cb59faf01,md5_hash
202133f65ddd420d04b178d9897efe86,md5_hash
8e4e775a95d23e5ae1afc6f4fbc3c920,md5_hash
d7bdbca88ef9257c3d41cca50593e700,md5_hash
bca85aa92492af2e836ee26f3a0a4e62,md5_hash
544fca6eb8181f163e2768c81f2ba0b3,md5_hash
6dfbfbce64510aaee3094da0aefe8a9b,md5_hash
e35de3008e9027d487dd0a598f651155,md5_hash
2de8b6bb8fa9d92ec315477491391a1f,md5_hash
58744dfbc581baa3d19853fe6388106d,md5_hash
48e58424be47d0c68fca63f15cea3d25,md5_hash
ef9df8fad4a02ec8c8c4bf8408585400,md5_hash
3db2a93d228d332b095379f1e40650ef,md5_hash
8a7bfeb0fe8e30d60c4c17b40871ebb2,md5_hash
d7b571ad08a6f704ff0dcc369c7ec4e6,md5_hash
12cad8963722580a55efcff6ceb96c3b,md5_hash
b346d7c6518ba62ddfdc6c070fbf421e,md5_hash
e27d2773c123596b23dabd9742f23b7b,md5_hash
43492ca6b1a420b682ab58e8a7d46d26,md5_hash
5e3eaca3806769836c3ad9d46a209644,md5_hash
a76419a2fca12427c887895e12a3442b,md5_hash
bf3d4cfee3e2d133ea73eda61fa534eb,md5_hash
4e11af053ff535873fa750c78f618340,md5_hash
54cdd6b60c940b389ccaa6263401c18e,md5_hash
42e21681754c60ab23d943cd89e9187d,md5_hash
11eb5246e237edd54a98147ed1986bc8,md5_hash
2111622fe5d058ec14e3081c039de739,md5_hash
e2ec95f80c12b252ccd00df60ea81024,md5_hash
3e0416a426a02de5335d9a2c808054fc,md5_hash
6ba850fac8785e902402b325d1579881,md5_hash
5b5da818513874b32c48c841208bc9d0,md5_hash
6e2dc6b0a6bed8fc62f3b649e6099818,md5_hash
42fa42472ebf01b4fbc82d2b16a889a0,md5_hash
9c88d2c223c700b47e3e666948002ce6,md5_hash
99cf0359c425b5123a572fcef97ea8f4,md5_hash
d1734c5e06e05b884b69f59566bd36ad,md5_hash
decc69ead3ed844ea8fab6c1c1b1f463,md5_hash
3459bc37967480dee405a5ac678b942d,md5_hash
5e94034804125cf7358a2dbe2939a71c,md5_hash
5abe124298be1b4728a277939544d0a3,md5_hash
c2d350c98408e861edfc8fd1f97c3546,md5_hash
15cae06fe5aa9934f96895739e38ca26,md5_hash
02f926acac9afbe3ccf13248ede5c1b3,md5_hash
c199533f978a6645fac38ac3be627868,md5_hash
6631815d4ab2a586021c24e02e5cc451,md5_hash
5425f69a977f4385ffd26b2e09afcc17,md5_hash
5bc8bdcf74107467fa0c7d96fe494db6,md5_hash
64311f8eeeccbd2453f92f0d1b63029c,md5_hash
73ca399985791e8041b0772d65ba70fd,md5_hash
569580e58ab5239e140fc88e145a30e3,md5_hash
b6f201184cad06faba5ad58950ee970d,md5_hash
fbbc8c66a57f1622104fb00beed2d4cb,md5_hash
ab3a49ef60948ccb1ee3cf672d6891c5,md5_hash
8410f8f773cc19d7fbfd7e065b761ae7,md5_hash
d43c93228fc1ebd2c8e985e96f808a12,md5_hash
3a0e2119aef11b229979871a1d1f6073,md5_hash
dd4799d54e23870901aef4cff9f2c676,md5_hash
1498ca75e0615c27026444685821bc28,md5_hash
8684c58605ee38f131568c414df2e2ba,md5_hash
02283022272d73fb0fea947da35f29b2,md5_hash
b9ca4f4ec95274ed15b16c3042a11ab5,md5_hash
81d91b93d7a1abe98fcb4f4e8a441d39,md5_hash
0ae187183008d3465dba182ff71102ad,md5_hash
2922b378066176b0ade6b756200937e0,md5_hash
9b6da1f57f471cee412ee6aa13d77848,md5_hash
d8129f9296b2f836b97ba5ff5b09cd3c,md5_hash
649995fa13168bcb718ba68cde0e6ed6,md5_hash
9bf37b30c701b447072b42219f08a0c7,md5_hash
4628121e786d2288ccaa0864568ed778,md5_hash
42bbe57b8de6d5e549eac10c2dccef88,md5_hash
f89eee2605969b9905be4d4ccb335f21,md5_hash
7071242821d43e86e640902c735c7559,md5_hash
fd24ee806ee7dcef9054790c4db40aeb,md5_hash
8b77b5849d100fc046acec8b4e74b2f8,md5_hash
2cb901ae51f7886e6974e296074c3c91,md5_hash
9e12a3ca24ecba10345ee57d6913387c,md5_hash
88ba4ad3dcae75b8ed7bc20dcd8fbf0b,md5_hash
a4239dab12d78bb2a11d36f6231ff3ab,md5_hash
116b93042da1c7dc8a29434f2d2f521a,md5_hash
66f96f2734c25653454d4517574ba750,md5_hash
2c9447bba8a5bf83b71bd3126718cf77,md5_hash
c794c0c2ce5aedfceaf971f389a24114,md5_hash
ef702dc02e81b35eaa2caa6c236da7a7,md5_hash
de50279578a1dc45d04987b1d60612fa,md5_hash
78ee93d344e1362e9f343b315fbf43a3,md5_hash
00bbe0d0d577a7682b7f9b3b21c07c8d,md5_hash
24a81f133353834be55a16b5313807e6,md5_hash
66298018d020736de7aa654db4a3c59d,md5_hash
6d7bdc024eb0b9aee72c49ee88aa41d2,md5_hash
33783a855618d3ffb44907bd77cf202e,md5_hash
3150af8e5358c12c1e9db8f4392fb990,md5_hash
dc58cdd0500cad7d9360aa96bbdd3b98,md5_hash
a6fea7c6305ecda36c5b9ccccd21f585,md5_hash
d6ae3fcbaff2a71f251ca81236a6c233,md5_hash
bf9d6675eed78e3a5af56d8bb0622107,md5_hash
10906ede324051cccbca2a60bcaa25c1,md5_hash
37287fa4b33a1c3913daedcde5557c99,md5_hash
594c297566407898c84be5183adc9766,md5_hash
76f5d45db6452fac59d5fbad3ff03d65,md5_hash
8eccfc6b84a70ae91e0ba128537ee490,md5_hash
9684b36b46561dd1763cc4f9402eaf37,md5_hash
24676f34692e70d6d58bb337813f4550,md5_hash
16a4198d4c0b01b42b505d2babb3c821,md5_hash
37905b21d2d1b6fdf60a93bb5b01e9f9,md5_hash
222d59b353b1df9375ba85cc7042cd26,md5_hash
dc5001d732a80552b032e35ce18572f1,md5_hash
ea7bdf2e5832cdde7d6a979584c9c574,md5_hash
8e2657e004c3ef29266e01cab41df78d,md5_hash
057e912732e5c98540dba1d76440ccca,md5_hash
85a41973867d83b94798e29fda4a3677,md5_hash
e0037673e8865c33ad6562b44c02099b,md5_hash
a5dfba7399dfe1b581838b97f6becff9,md5_hash
145a58b6d55df940dc7e7233201b79bb,md5_hash
6f8ecd6aea161e081356a468fc710b68,md5_hash
9cd5f4a00984eab51e3f615bf3e1e5d3,md5_hash
b3948022fb3624971bee68e5c2e6da44,md5_hash
3fd2dfa0c1658fbd2f77dd11731108c2,md5_hash
2a4d65825a278ce978744a57a36793aa,md5_hash
bd047b6756a813f7f66b7fac837224c5,md5_hash
0b7d8d1fc28f65ebee6d61fb477e28b6,md5_hash
4b86bdd4059576d75bbeb91ed3851928,md5_hash
ead400deb12928c03d6fc4731fe59232,md5_hash
98f721d3d25adb1a8f88ccad287582ce,md5_hash
4275e025f350c830281ec03777db2b69,md5_hash
c6d09f05abc7af645832b18b5bc402b2,md5_hash
da0e8a54fd5da2c957f305be63f0dbd5,md5_hash
a98f9507ec79a93d2877182f39b7eb69,md5_hash
f7908bbd22912f1fd5dc4ee99d24d464,md5_hash
9e258fe2696e4fe2470015f79b90f183,md5_hash
a0559d54b1eef139d199221b08e3deee,md5_hash
b72f3bd15cd351a75307d9f8e1fa0618,md5_hash
bd7779f11e6b679aba43e1ca5313351a,md5_hash
e59a95dd5f23a8733f31b8a43b058548,md5_hash
600197a8de5fa5b4eb63301ab8173688,md5_hash
app.stream-media.net,domain
update.konamidata.com,domain
apps.anyoffice.info,domain
chat.feiloglobe.com,domain
chat.gamemuster.com,domain
ctrl.t008.net,domain
globe.t008.net,domain
halloween.bmwauto.org,domain
hide.kyoceras.net,domain
ilime.raylitoday.com,domain
news.feiloglobe.com,domain
qiqi.t008.net,domain
radio.gamemuster.com,domain
resell.siseau.com,domain
sat.nestlere.com,domain
sports.feiloglobe.com,domain
survey.ctable.org,domain
temp.renewgis.com,domain
vivian.t008.net,domain
web.t008.net,domain
wins.windowsupdote.net,domain
web.creativezh.com,domain
app.sst1.info,domain
files.satelliteclub.info,domain
kind.anyoffice.info,domain
file.it-bar.net,domain
app.jj-desk.com,domain
download.jj-desk.com,domain
tools.space-today.info,domain
tech.decipherment.net,domain
hide.konamidata.com,domain
drizl.konamidata.com,domain
vista.konamidata.com,domain
youth.konamidata.com,domain
control.konamidata.com,domain
ardo.namcodat.com,domain
cti.anfoundation.us,domain
dnke.succourtion.org,domain
guest.anfoundation.us,domain
lais.rwchateau.com,domain
mail.hfmforum.com,domain
maya.cultivr.com,domain
nsc.adomhn.com,domain
orb.vssigma.com,domain
pl.anfoundation.us,domain
sun.succourtion.org,domain
tnv.cultivr.com,domain
tps.cultivr.com,domain
www.hgcurtain.com,domain
www.psactel.com,domain
southern.siue.edu.myfw.us,domain
login.stream-media.net,domain
www.artistryinprint.com,domain
www.diam.unina2.net,domain
root.awebers.com,domain
tools.ics-no.org,domain
file.anyoffice.info,domain
down72.xafsl5.org,domain
tool.sst1.info,domain
member.satelliteclub.info,domain
queen1.xafsl5.org,domain
sports.graceland-siu.org,domain
sunny.tensins.net,domain
www3.cbssrayli.com,domain
gis.tensins.net,domain
jamstec.tensins.net,domain
deb.vssigma.com,domain
rj.cbssrayli.com,domain
www5.cbssrayli.com,domain
tkcht.checalla.com,domain
sports.tensins.net,domain
great.vssigma.com,domain
red.vssigma.com,domain
server.ics-no.org,domain
west.ics-no.org,domain
frag.succourtion.org,domain
ftp.dnstrans.proxydns.com,domain
download.eldaedu.us,domain
toch.anfoundation.us,domain
once.ptkstore.com,domain
google.hgcurtain.com,domain
www.bibleevidence.com,domain
134.129.140.212,ip_address
140.112.19.195,ip_address
210.7.26.67,ip_address
140.113.241.33,ip_address
59.120.168.199,ip_address
211.75.57.130,ip_address
140.113.88.216,ip_address
212.154.133.102,ip_address
220.117.69.82,ip_address
202.143.176.7,ip_address
220.117.69.237,ip_address
220.117.69.85,ip_address
210.7.26.58,ip_address
140.112.40.7,ip_address
67.42.255.50,ip_address
211.21.91.62,ip_address
202.215.53.178,ip_address
206.182.217.202,ip_address
61.221.54.99,ip_address
140.119.46.35,ip_address
212.48.149.57,ip_address
202.152.165.221,ip_address
61.34.97.69,ip_address
210.16.204.170,ip_address
221.161.158.1,ip_address
61.74.190.14,ip_address
173.231.36.139,ip_address
219.253.24.100,ip_address
61.78.75.96,ip_address
222.107.91.130,ip_address
210.200.19.99,ip_address
219.253.24.92,ip_address
204.12.192.236,ip_address
173.252.207.51,ip_address
121.157.104.122,ip_address
173.252.205.56,ip_address
208.110.66.71,ip_address
61.78.37.121,ip_address
173.208.242.84,ip_address