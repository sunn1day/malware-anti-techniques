// antidebug.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "pch.h"

VOID exec_check(int(*callback)(), const TCHAR* szMsg)
{
	const TCHAR* format = TEXT("[+] %s\n");
	_tprintf(format, szMsg);
	unsigned int result = callback();
	printf("Result (0:Not found, Otherwise found):%d\n\n", result);
}

int _tmain(int argc, _TCHAR* argv[])
{
	exec_check(&IsDebuggerPresentPEB, TEXT("IsDebuggerPresentPEB"));
	exec_check(&adbg_BeingDebuggedPEB, TEXT("adbg_BeingDebuggedPEB"));
	exec_check(&adbg_IsDebuggerPresent, TEXT("adbg_IsDebuggerPresent"));
	exec_check(&CheckRemoteDebuggerPresentAPI, TEXT("CheckRemoteDebuggerPresentAPI"));
	exec_check(&adbg_CheckWindowName, TEXT("adbg_CheckWindowName"));
	exec_check(&adbg_NtGlobalFlagPEB, TEXT("adbg_NtGlobalFlagPEB"));

	return 0;
}

