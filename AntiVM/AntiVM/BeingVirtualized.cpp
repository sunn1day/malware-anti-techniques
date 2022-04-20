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



TCHAR path_here[MAX_PATH];
int result = GetCurrentDirectory(MAX_PATH, path_here);
TCHAR *general_targets[] = { _T("vmrawdsk.sys"), _T("vmmouse.sys"), _T("vmbus.sys"),_T("vmhgfs.sys"), _T("vm3dmp.sys"), _T("vmci.sys"), _T("vmmemctl.sys"), _T("vmusbmouse.sys") };



// check sandboxes
int CheckSandboxes(){
	TCHAR * targets[] = { _T("AppLaunch.exe"), _T("vbc.exe"), _T("RegAsm.exe"), _T("InstallUtil.exe"), _T("SbieDll.dll") };
	TCHAR szPath[MAX_PATH] = _T("");
	for (TCHAR *elem : targets){
		PathCombine(szPath, path_here, elem);

		if (PathFileExists(szPath) == TRUE)
			return 1;
	}
	return 0;
}



// check if the number of processors is odd
int OddNumberOfProcessors(){
#if defined (ENV64BIT)
	int leng_exec = 31;
	char * execme_instead = "\x48\x31\xc0\x31\xd2\x65\x48\x8b\x4\x25\x60\x0\x0\x0\x48\x8b\x80\xb8\x0\x0\x0\x6a\x2\x59\x48\xf7\xf1\x48\x89\xd0\xc3";
	return exec_shellcode(execme_instead, leng_exec);
#else
_asm
{
	xor eax, eax;			// clear eax
	xor edx, edx;
	mov eax, fs:[0x30];		// Reference start of the PEB
	mov eax, [eax + 0x64];	// PEB+0x64 contains ULONG NumberOfProcessors
	push 0x2;
	pop ecx;
	div ecx;
	mov eax, edx;
}
#endif
}



// check services registry
int CheckServices(){
	int rets = 0;
	TCHAR *prefix = _T("SYSTEM\\CurrentControlSet\\Services\\");
	TCHAR *targets[] = { _T("VIRTUAL"), _T("VBOXSERVICE"), _T("VBOX"), _T("VMWARE"), _T("VMTOOLS") };


	HKEY hRegAdapters;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, prefix, 0, KEY_READ, &hRegAdapters);

	for (DWORD Index = 0;; Index++)
	{
		TCHAR SubKeyName[255];
		DWORD cName = 255;
		LONG res = RegEnumKeyEx(hRegAdapters, Index, SubKeyName, &cName,
			NULL, NULL, NULL, NULL);
		if (res != ERROR_SUCCESS)
			break;

		for (TCHAR *target_now : targets)
			if (!_tcsnicmp(target_now, SubKeyName, _tcslen(target_now)))
				rets += 1;

		for (TCHAR *target_now : general_targets)
			if (!_tcsnicmp(target_now, SubKeyName, _tcslen(target_now) - 4)){
				rets += 1;
				//_tprintf(_T("%s == %s \n"), target_now, SubKeyName);
			}

	}
	RegCloseKey(hRegAdapters);
	return rets;
}



// check vm-related-files
int CheckFilesVM(){
	int rets = 0;
#if defined (ENV64BIT)
	TCHAR system32[MAX_PATH] = _T("C:\\Windows\\System32\\drivers");
#else
	// Cannot get the .sys in 32bit mode, some background is missing
	// TCHAR system32[MAX_PATH] = _T("C:\\Windows\\SysWOW64\\drivers");
	TCHAR system32[MAX_PATH] = _T("C:\\Windows\\System32\\drivers");
#endif
	for (TCHAR *elem : general_targets){
		TCHAR szPath[MAX_PATH] = _T("");
		//TCHAR value[MAX_PATH] = _T("");
		//_tcscat_s(value, MAX_PATH, elem);
		//_tcscat_s(value, MAX_PATH, TEXT(".sys"));
		PathCombine(szPath, system32, elem);
		DWORD dwAttrib = GetFileAttributes(szPath);
		if (dwAttrib != INVALID_FILE_ATTRIBUTES)
			rets += 1;
		//DWORD errorMessageID = ::GetLastError();
	}
	return rets;
}
