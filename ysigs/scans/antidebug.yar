rule DebuggerCheck__API : AntiDebug DebuggerCheck {
	meta:
		weight = 1
	strings:
		$ ="IsDebuggerPresent"
	condition:
		any of them
}

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
	meta:
		weight = 1
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
	meta:
		weight = 1
	strings:
		$ ="NtGlobalFlags"
	condition:
		any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
	meta:
		weight = 1
	strings:
		$ ="QueryInformationProcess"
	condition:
		any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
	meta:
		weight = 1
	strings:
		$ ="CheckRemoteDebuggerPresent"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
	meta:
		weight = 1
	strings:
		$ ="SetInformationThread"
	condition:
		any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
	meta:
		weight = 1
	strings:
		$ ="DebugActiveProcess"
	condition:
		any of them
}

rule DebuggerTiming__PerformanceCounter : AntiDebug DebuggerTiming {
	meta:
		weight = 1
	strings:
		$ ="QueryPerformanceCounter"
	condition:
		any of them
}

rule DebuggerTiming__Ticks : AntiDebug DebuggerTiming {
	meta:
		weight = 1
	strings:
		$ ="GetTickCount"
	condition:
		any of them
}

rule DebuggerOutput__String : AntiDebug DebuggerOutput {
	meta:
		weight = 1
	strings:
		$ ="OutputDebugString"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerException__UnhandledFilter : AntiDebug DebuggerException {
	meta:
		weight = 1
	strings:
		$ ="SetUnhandledExceptionFilter"
	condition:
		any of them
}

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
	strings:
		$ ="GenerateConsoleCtrlEvent"
	condition:
		any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule ThreadControl__Context : AntiDebug ThreadControl {
	meta:
		weight = 1
	strings:
		$ ="SetThreadContext"
	condition:
		any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
	meta:
		weight = 1
	strings:
		$ ="__invoke__watson"
	condition:
		any of them
}

rule SEH__v3 : AntiDebug SEH {
	meta:
		weight = 1
	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"
	condition:
		any of them
}

rule SEH__v4 : AntiDebug SEH {
    // VS 8.0+
	meta:
		weight = 1
	strings:
		$ = "____except__handler4"
		$ = "____local__unwind4"
		$ = "__XcptFilter"
	condition:
		any of them
}

rule SEH__vba : AntiDebug SEH {
	meta:
		weight = 1
	strings:
		$ = "vbaExceptHandler"
	condition:
		any of them
}

rule SEH__vectored : AntiDebug SEH {
	meta:
		weight = 1
	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
// Patterns
rule DebuggerPattern__RDTSC : AntiDebug DebuggerPattern {
	meta:
		weight = 1
	strings:
		$ = {0F 31}
	condition:
		any of them
}

rule DebuggerPattern__CPUID : AntiDebug DebuggerPattern {
	meta:
		weight = 1
	strings:
		$ = {0F A2}
	condition:
		any of them
}

rule DebuggerPattern__SEH_Saves : AntiDebug DebuggerPattern {
	meta:
		weight = 1
	strings:
		$ = {64 ff 35 00 00 00 00}
	condition:
		any of them
}

rule DebuggerPattern__SEH_Inits : AntiDebug DebuggerPattern {
	meta:
		weight = 1
	strings:
		$ = {64 89 25 00 00 00 00}
	condition:
		any of them
}


rule dbgdetect_funcs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$func1 = "IsDebuggerPresent"
		$func2 = "OutputDebugString"
		$func3 = "ZwQuerySystemInformation"
		$func4 = "ZwQueryInformationProcess"
		$func5 = "IsDebugged"
		$func6 = "NtGlobalFlags"
		$func7 = "CheckRemoteDebuggerPresent"
		$func8 = "SetInformationThread"
		$func9 = "DebugActiveProcess"

	condition:
		2 of them
}

rule dbgdetect_procs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$proc1 = "wireshark" nocase ascii wide
		$proc2 = "filemon" nocase ascii wide
		$proc3 = "procexp" nocase ascii wide
		$proc4 = "procmon" nocase ascii wide
		$proc5 = "regmon" nocase ascii wide
		$proc6 = "idag" nocase ascii wide
		$proc7 = "immunitydebugger" nocase ascii wide
		$proc8 = "ollydbg" nocase ascii wide
		$proc9 = "petools" nocase ascii wide

	condition:
		2 of them
}

rule dbgdetect_files : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"
	strings:
		$file1 = "syserdbgmsg" nocase ascii wide
		$file2 = "syserboot" nocase ascii wide
		$file3 = "SICE" nocase ascii wide
		$file4 = "NTICE" nocase ascii wide
	condition:
		2 of them
}

