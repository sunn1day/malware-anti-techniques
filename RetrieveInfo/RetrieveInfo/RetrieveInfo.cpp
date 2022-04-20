// RetrieveInfo.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "pch.h"


void _tmain(void)
{
	struct __RetInfo p1;
	TCHAR * error_code;

	
	if (!retComputerName(p1.netName, &(p1.netSize))){
		error_code = TEXT("GetComputerNameEx failed (%d)\n");
		goto _exit_path;
	}

	retVersionsBuild(_ptr(p1, dwMajorVersion), _ptr(p1, dwMinorVersion), _ptr(p1, dwBuildNumber));
	
	getCpuClock(_ptr(p1,diff_tsc));

	getMacAddresses(_ptr(p1,mac_addr_list));
	
	print_info(&p1);

	return;
	_exit_path:
		_tprintf(error_code, GetLastError());
		ExitProcess(2);
}


