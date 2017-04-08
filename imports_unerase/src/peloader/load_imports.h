#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <map>

#include "pe_hdrs_helper.h"

bool is_supported(LPSTR lib_name);

bool write_handle(LPCSTR lib_name, ULONGLONG call_via, LPSTR func_name, LPVOID modulePtr, bool is64);

bool solve_imported_funcs_b32(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr);
bool solve_imported_funcs_b64(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr);

char* get_exported_func(PVOID modulePtr, ULONGLONG searchedRVA);
bool fix_imports(PVOID modulePtr, std::map<ULONGLONG, MODULEENTRY32> modulesMap);