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
include "malware/androidRat.yar"
include "malware/Asprox.yar"
include "malware/backoff.yar"
include "malware/blackhole_exploit_kit.yar"
include "malware/botnethunter.yar"
include "malware/callTogether_certificate.yar"
include "malware/cleaver.yar"
include "malware/cnGUIscanner.yar"
include "malware/contagio.yar"
include "malware/cridexGeneric.yar"
include "malware/crowdstrike.yar"
include "malware/cve.yar"
include "malware/DarkComet.yar"
include "malware/darkmoon.yar"
include "malware/derusbi.yar"
include "malware/derusbiserver.yar"
include "malware/Dyre_Delivery.yar"
include "malware/dyre.yar"
include "malware/exploits.yar"
include "malware/fexel.yar"
include "malware/fpu.yar"
include "malware/gresim.yar"
include "malware/havexrat.yar"
include "malware/hiddenlynxfiles.yar"
include "malware/hikit.yar"
include "malware/ibanking.yar"
include "malware/inception.yar"
include "malware/kelihos.yar"
include "malware/kevinbreen.yar"
include	"malware/malicious_macros.yar"
include "malware/malware-certs.yar"
include "malware/moudoor.yar"
include "malware/naid.yar"
include "malware/nanocoreRat.yar"
include "malware/nettraveler.yar"
include "malware/neurevt.yar"
include "malware/Novetta_OpSMN.yar"
include "malware/OnAndOn_cert.yar"
include "malware/plugindetect.yar"
include "malware/PM_Zip_With_Exe.yar"
include "malware/powerliks.yar"
include "malware/qti_certificate.yar"
include "malware/RedOctober_CloudAtlas_ctfmonrn.yar"
include "malware/regin.yar"
include "malware/scrazemalware.yar"
include "malware/shellcrew.yar"
include	"malware/skeleton_key.yar"
include "malware/threatconnect.yar"
include "malware/win_Gh0st_ver2.yar"
include "malware/windows0dayexploit.yar"
include "malware/wipbot.yar"
include "malware/wiper.yar"
include "malware/xplug.yar"
include "malware/zeus2.yar"
include "malware/zeus1134.yar"
include "malware/zox.yar"




//
// Attack signatures
include "ysigs/MSSUP-AST.yar"
include "ysigs/heartbleed.yar"



//
// EOF
