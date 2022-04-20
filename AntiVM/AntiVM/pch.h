#ifndef PCH_H
#define PCH_H


#include <Windows.h>
#include <winternl.h>

#include "Shlwapi.h"
#pragma comment(lib, "Shlwapi.lib")

#include <string.h>

int CheckSandboxes();
int OddNumberOfProcessors();
int CheckServices();
int CheckFilesVM();

#endif PCH_H