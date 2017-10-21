#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <map>

#include "pe_hdrs_helper.h"
#include "exports_lookup.h"

bool fixImports(PVOID modulePtr, size_t moduleSize, std::map<ULONGLONG, std::set<ExportedFunc>> &va_to_func);
