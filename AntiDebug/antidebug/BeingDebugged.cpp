#include "stdafx.h"
#include "pch.h"


//#define ENV64BIT

//64bit inline
static const int size_def = 0x200;
static LPVOID shellcodes = (BYTE *)VirtualAlloc(NULL, size_def, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

unsigned int exec_shellcode(char* shellc, int size_from){
	memset(shellcodes, 0, size_def);
	memcpy(shellcodes, shellc, size_from);
	auto pFunc = (unsigned int(*)()) (void*)shellcodes;
	return pFunc();
}



/* @@ IsDebuggerPresentPEB

Checks if the BeingDebugged flag is set in the Process Environment Block (PEB).
This is effectively the same code that IsDebuggerPresent() executes internally.
The PEB pointer is fetched from:
	- DWORD FS:[0x30] on x86_32
	- QWORD GS:[0x60] on x86_64.
	
// Bypass:
	Once the BeingDebugged byte in the PEB is queried, flip the value from 1 to 0 before it is evaluated by the application logic.
*/
int IsDebuggerPresentPEB( VOID )
{
#if defined (ENV64BIT)
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30); //return 32 bit version as default

#endif

	return pPeb->BeingDebugged;
}



/* @@ adbg_BeingDebuggedPEB

Equivalent to IsDebuggerPresentPEB
*/
int adbg_BeingDebuggedPEB(void)
{
	short int found = FALSE;
#if defined (ENV64BIT)
	//Not supported inline assembly C++ in x64 and ARM
	/*
	_asm
	{
		xor rax, rax;
		xor rbx, rbx;
		mov rax, gs:[0x60];
		mov rax, [rax + 0x2];
		mov bl, 0xff;
		and rax, rbx;
	}
	*/
	int leng_exec = 25;
	/*Issue with mov rax, gs:[0x60] that was assembled in: "\x65\x8b\x05\x60\x00\x00\x00"  but that is mov eax,[rel gs:0x67]
		The right opcode is: "\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
	*/
	char * execme_instead = "\x48\x31\xc0\x48\x31\xdb\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x02\xb3\xff\x48" \
		"\x21\xd8\xc3";
	
	return exec_shellcode(execme_instead, leng_exec);
#else
	 _asm
	{
		xor eax, eax;			// clear eax
		xor ebx, ebx;
		mov eax, fs:[0x30];		// Reference start of the PEB
		mov eax, [eax + 0x02];	// PEB+2 points to BeingDebugged
		mov bl, 0xff;
		and eax, ebx;
	}
#endif
}



/* @@adbg_IsDebuggerPresent

Equivalent to adbg_BeingDebuggedPEB
*/
int adbg_IsDebuggerPresent(void)
{
	BOOL found = FALSE;
	found = IsDebuggerPresent();

	return found;
}



/* @@CheckRemoteDebuggerPresentAPI
CheckRemoteDebuggerPresent() is another Win32 Debugging API function; it can be used to check if a remote process is being debugged. 
However, we can also use this as another method for checking if our own process is being debugged. 
This API internally calls the NTDLL export NtQueryInformationProcess function with the SYSTEM_INFORMATION_CLASS set to 7 (ProcessDebugPort).

// Bypass:
 Set a breakpoint on CheckRemoteDebuggerPresent(), single step,
 then switch the return value to 0.

*/
int CheckRemoteDebuggerPresentAPI(VOID)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	BOOL found = FALSE;

	hProcess = GetCurrentProcess();
	CheckRemoteDebuggerPresent(hProcess, &found);

	return found;
}



/* @@adbg_CheckWindowName
Checks for a window with a specific Class name. This name is
not the title of the Window. Use tools like Nirsoft Winlister to find this value.

// Bypass:
 Set a breakpoint on FindWindow, single step, then
 switch the return value to 0.
*/
int adbg_CheckWindowName(void)
{
	int found = 0;
	HANDLE hWindow = NULL;
	wchar_t *WindowClassNameIDA = L"Qt5QWindowIcon";	// IDA Pro
	wchar_t *WindowClassNameOlly = L"OLLYDBG";			// OllyDbg
	wchar_t *WindowClassNameImmunity = L"ID";			// Immunity Debugger
	wchar_t *WindowClassNameWinDbg = L"WINDBG";			// WinDbg

	// Check for IDA Pro
	hWindow = FindWindow(WindowClassNameIDA, 0);
	if (hWindow)
	{
		found = 1;
	}

	// Check for OllyDBG
	hWindow = FindWindow(WindowClassNameOlly, 0);
	if (hWindow)
	{
		found = 1;
	}

	// Check for Immunity
	hWindow = FindWindow(WindowClassNameImmunity, 0);
	if (hWindow)
	{
		found = 1;
	}

	// Check for WinDbg
	hWindow = FindWindow(WindowClassNameWinDbg, 0);
	if (hWindow)
	{
		found = 1;
	}

	return found;
}



/* @@abdg_NtGlobalFlagPEB

Look for Process Environment Block(PEB) references, so:
	- The FS segment points to the Thread information block
	- FS stands for "Frame Segment" and generally indicates references to an application's own internal header structures
	- FS:[0x30] (x86_32)	GS:[0x60]  (x86_64) contains linear address of PEB
	- On 32 bit Windows GS is reserved for future use
	- In x64 mode the FS and GS segment registers have been swapped around
	- In x86 mode FS:[0] points to the start of the TIB, in X64 it's GS:[0]
	- The reason Win64 uses GS is that there the FS register is used in the 32 bit compatibility layer (confusingly called Wow64)

These should not raise red flags, however they should be noted:
	- 0x68 offset from the PEB is the NtGlobalFlag value, instead in x86_64 it starts 0xBC offset
	- When a process is being debugged, three flags are set:
		- FLG_HEAP_ENABLE_TAIL_CHECK(0x10)
		- FLG_HEAP_ENABLE_FREE_CHECK(0x20)
		- FLG_HEAP_VALIDATE_PARAMETERS(0x40)

// Bypass:
	the same seen before..
*/
int adbg_NtGlobalFlagPEB(void)
{
	short int found = FALSE;
#if defined (ENV64BIT)
	//Not supported inline assembly C++ in x64 and ARM
	/* echo -ne "xor rax, rax; ....; and rax, rbx;' | rasm2 -a x86 -C -b 64 -
	_asm
	{
		xor rax, rax;
		xor rbx, rbx;
		mov rax, gs:[0x60];
		mov rax, [rax + 0xbc];
		and al, 0x70;
		mov bl, 0xff;
		and rax, rbx;
	}
	*/
	int leng_exec = 30;
	char * execme_instead = "\x48\x31\xc0\x48\x31\xdb\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8b\x80\xbc\x00\x00\x00" \
		"\x24\x70\xb3\xff\x48\x21\xd8\xc3";
	return exec_shellcode(execme_instead, leng_exec);
#else
	_asm
	{
		xor eax, eax;			// clear eax
		xor ebx, ebx;
		mov eax, fs:[0x30];		// Reference start of the PEB
		mov eax, [eax + 0x68];	// PEB+0x68 points to NtGlobalFlags
		mov bl, 0x70;
		and eax, ebx;			// check three flags
	}
#endif
}


