/* Global Rule -------------------------------------------------------------- */
/* Will be evaluated first, speeds up scanning process, remove at will */

global private rule gen_characteristics {  
    condition:
        uint16(0) == 0x457f and filesize < 7429KB
}

/* Rule Set ----------------------------------------------------------------- */

rule _Users_Brian_vagrant_ubuntu_64_analysis_rr_rrrr {  
    meta:
        description = "Auto-generated rule - file rrrr.1"
        author = "YarGen Rule Generator"
        reference = "not set"
        date = "2015-06-12"
        hash = "536b282fb9990451fc08a7a827c688c6c385bf63"
    strings:
        $s0 = "_ZN14CThreadHttpGet11ProcessMainEv" fullword ascii
        $s1 = "_ZN19CThreadFXConnection17GetFakeDetectPortEv" fullword ascii
        $s2 = "_ZN17CThreadConnection17GetFakeDetectPortEv" fullword ascii
        $s3 = "_ZN17CThreadFakeDetect11ProcessMainEv" fullword ascii
        $s4 = "ThreadHttpGet.cpp" fullword ascii
        $s5 = "_ZN14CThreadRecycle11ProcessMainEv" fullword ascii
        $s6 = "_ZN19CThreadShellRecycle11ProcessMainEv" fullword ascii
        $s7 = "_ZN8CManager19RecycleShellProcessEv" fullword ascii
        $s8 = "_ZN15CFakeDetectInfo17GetFakeDetectPortEv" fullword ascii
        $s9 = "_ZN14CThreadLoopCmd11ProcessMainEv" fullword ascii
        $s10 = "_ZNSt18_Vector_alloc_baseIP14CThreadHttpGetSaIS1_ELb1EEC2ERKS2_" fullword ascii
        $s11 = "_ZN8CManager19DoFakeDetectCommandEP7CCmdMsg" fullword ascii
        $s12 = "_ZN17CThreadFakeDetect16SetFakeDetectCmdER15CFakeDetectInfo" fullword ascii
        $s13 = "_ZSt11__copy_aux2IP14CThreadHttpGetEPT_S3_S3_S3_11__true_type" fullword ascii
        $s14 = "_ZSt19__copy_backward_auxIPP14CThreadHttpGetS2_ET0_T_S4_S3_" fullword ascii
        $s15 = "_ZSt13__destroy_auxIPP14CThreadHttpGetEvT_S3_11__true_type" fullword ascii
        $s16 = "relocation processing: %s%s" fullword ascii
        $s17 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
        $s18 = "ELF load command address/offset not properly aligned" fullword ascii
        $s19 = "_ZN8CManager14RecycleProcessEv" fullword ascii
        $s20 = "_ZNSt12_Vector_baseIP14CThreadHttpGetSaIS1_EED2Ev" fullword ascii
    condition:
        uint16(0) == 0x457f and filesize < 7429KB and all of them
}
