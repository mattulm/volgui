// Master YARA rule.
// Last updated: 2014-10-26


//
// Some generic searches
include "ysigs/shellcodes.yar"
include "ysigs/sandboxdetect.yar"
include "ysigs/vmdetect.yar"
include "ysigs/antidebug.yar"
include "ysigs/packer.yar"
include "ysigs/compiler.yar"
include "ysigs/default_signatures.yar"
include "ysigs/embedded.yar"
include "ysigs/amagic.yar"
include "ysigs/capabilities.yar"
include "ysigs/carva.yar"
include "ysigs/compiled_autoit.yar"
include "ysigs/compression.yar"
include "ysigs/connection_manager_phonebook.yar"
include "ysigs/pcre.yar"
include "ysigs/reads_clipboard.yar"
include "ysigs/winsockets.yar"
include "ysigs/lowerssecurity.yar"
include "ysigs/http.yar"
include "ysigs/avdetection.yar"
include "ysigs/adware.yar"


//
// Other OS signatures
include "ysigs/linux.yar"
include "ysigs/osx.yar"
include "ysigs/windigoonimiki.yar"


//
// Misc YARA rules for specific cases
include "ysigs/apacheInjection.yar"
include "ysigs/posmalware.yar"


//
// Below are hashing constants to check for
include "ysigs/blowfish.yar"
include "ysigs/md5.yar"
include "ysigs/rc6.yar"
include "ysigs/ripemd160.yar"
include "ysigs/sha1.yar"
include "ysigs/sha256.yar"
include "ysigs/sha512.yar"

// 
// Large Malware listing
include "ysigs/infected.yar"

//
// Malware specific signatures
include "ysigs/dynamicdns.yar"
include "ysigs/botnethunter.yar"
include "ysigs/contagio.yar"
include "ysigs/crowdstrike.yar"
include "ysigs/flyingkitteniranianapt.yar"
include "ysigs/havexrat.yar"
include "ysigs/kevinbreen.yar"
include "ysigs/scrazemalware.yar"
include "ysigs/shellcrew.yar"
include "ysigs/threatconnect.yar"
include "ysigs/zeusbotnet.yar"
include "ysigs/cve.yar"
include "ysigs/exploits.yar"
include "ysigs/fpu.yar"
include "ysigs/msfrules.yar"
include "ysigs/plugindetect.yar"
include "ysigs/remoteshells.yar"
include "ysigs/wce.yar"
include "ysigs/webshells.yar"
include "ysigs/xplug.yar"
include "ysigs/autoItscript.yar"
include "ysigs/ibanking.yar"
include "ysigs/kelihos.yar"
include "ysigs/nettraveler.yar"
include "ysigs/neurevt.yar"
include "ysigs/poscardstealerspybot.yar"
include "ysigs/rc6constants.yar"
include "ysigs/windows0dayexploit.yar"
include "ysigs/zeus2.yar"
include "ysigs/zeus1134.yar"
include "ysigs/naid.yar"
include "ysigs/hikit.yar"
include "ysigs/moudoor.yar"
include "ysigs/gresim.yar"
include "ysigs/fexel.yar"
include "ysigs/derusbi.yar"
include "ysigs/zox.yar"
include "ysigs/hidkit.yar"
include "ysigs/derusbiserver.yar"




//
// Attack signatures
include "ysigs/MSSUP-AST.yar"
include "ysigs/heartbleed.yar"



//
// EOF
