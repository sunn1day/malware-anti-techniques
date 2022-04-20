#ifndef PCH_H
#define PCH_H


#include <stdio.h>
#include <tchar.h>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <Windows.h>
#include <winternl.h>


#pragma comment(lib, "ws2_32.lib")


#define __size_retInfo 256
struct __RetInfo {
	TCHAR netName[__size_retInfo];
	DWORD netSize= __size_retInfo;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	DWORD dwBuildNumber;
	UINT32 diff_tsc;
	struct mac_addr *mac_addr_list;
};

struct mac_addr
{
	BYTE                               PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH];
	ULONG                              PhysicalAddressLength;
	mac_addr *next;
};

#define _ptr(_x, _y) &(_x._y)

int retComputerName(TCHAR *ptr, DWORD * dwSize);
void retVersionsBuild(DWORD* dwMajorVersion, DWORD* dwMinorVersion, DWORD* dwBuildNumber);
void print_info(struct __RetInfo * p1);
void getCpuClock(UINT32 * tsc);
void getMacAddresses(struct mac_addr ** rets);

#endif PCH_H