// AntiVM.cpp : Defines the entry point for the console application.
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
	exec_check(&CheckSandboxes, TEXT("CheckSandboxes"));
	exec_check(&OddNumberOfProcessors, TEXT("OddNumberOfProcessors"));
	exec_check(&CheckServices, TEXT("CheckServices"));
	exec_check(&CheckFilesVM, TEXT("CheckFilesVM"));
	
	return 0;
}

