#ifndef PCH_H
#define PCH_H

#include <string>
#include <vector>

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memoryapi.h>
#include <memory.h>
#include <stdio.h>


int IsDebuggerPresentPEB(VOID);
int adbg_BeingDebuggedPEB(void);
int adbg_IsDebuggerPresent(void);
int CheckRemoteDebuggerPresentAPI(VOID);
int adbg_CheckWindowName(void);
int adbg_NtGlobalFlagPEB(void);



#endif //PCH_H