
#include "pch.h"


int retComputerName(TCHAR *ptr, DWORD * dwSize)
{
	// return NetBIOS name
	ZeroMemory(ptr, *dwSize);
	return GetComputerName(ptr, dwSize);
}

void retVersionsBuild(DWORD* dwMajorVersion, DWORD* dwMinorVersion, DWORD* dwBuildNumber) 
{
	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);

	*dwMajorVersion = osvi.dwMajorVersion;
	*dwMinorVersion = osvi.dwMinorVersion;
	*dwBuildNumber = osvi.dwBuildNumber;
}

void getCpuClock(UINT32 * diff_tsc){
	UINT32 cnt = 0;
	ULONG64 tsc1, tsc2;
	for (int i = 0; i < 3; i++){
		tsc1 = __rdtsc();
		HeapAlloc(GetProcessHeap(), 0, 3000);
		tsc2 = __rdtsc();
		cnt += (tsc2 - tsc1);
	}
	*diff_tsc = cnt / 3;
}

void getMacAddresses(struct mac_addr ** rets){

	int i;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	DWORD dwRetVal = 0;
	ULONG outBufLen = 0;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

	ULONG family = AF_INET;
	outBufLen = 15000;

	pAddresses = (IP_ADAPTER_ADDRESSES *) HeapAlloc(GetProcessHeap(), 0, outBufLen);
	dwRetVal = GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
	
	struct mac_addr *tail = NULL, *tmp_mac = NULL;

	if (dwRetVal == NO_ERROR) {
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {
			if (pCurrAddresses->PhysicalAddressLength != 0) {

				tmp_mac=(struct mac_addr *)HeapAlloc(GetProcessHeap(), 0, sizeof(struct mac_addr));
				tmp_mac->PhysicalAddressLength = pCurrAddresses->PhysicalAddressLength;

				for (i = 0; i < pCurrAddresses->PhysicalAddressLength;i++)
						tmp_mac->PhysicalAddress[i] = pCurrAddresses->PhysicalAddress[i];

				tmp_mac->next = tail;
				tail = tmp_mac;
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
	}
	HeapFree(GetProcessHeap(), 0, pAddresses);
	*rets = (struct mac_addr *)tail;
}


void print_info(struct __RetInfo * p1){

	int i;
	struct mac_addr *mac_now = p1->mac_addr_list;
	_tprintf(TEXT("NetBIOS:%s, Major version:%d, Minor version:%d, Build number:%d, TSC diff:%u\n"), p1->netName, p1->dwMajorVersion, p1->dwMinorVersion, p1->dwBuildNumber, p1->diff_tsc);
	_tprintf(TEXT("Physical address: {"));
	while (mac_now){
		if (mac_now->PhysicalAddressLength != 0) {
			_tprintf(TEXT(" \""));
			for (i = 0; i < mac_now->PhysicalAddressLength; i++) {
				if (i == (mac_now->PhysicalAddressLength - 1))
					_tprintf(TEXT("%.2X\""),(int)mac_now->PhysicalAddress[i]);
				else
					_tprintf(TEXT("%.2X-"),(int)mac_now->PhysicalAddress[i]);
			}
		}
		mac_now = mac_now->next;
	}
	_tprintf(TEXT("}"));



	_tprintf(TEXT("\n"));
}