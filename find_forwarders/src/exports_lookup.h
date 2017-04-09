#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <map>
#include <set>

#include "peloader/pe_hdrs_helper.h"
#include "peloader/pe_raw_to_virtual.h"

size_t forwarderNameLen(BYTE* fPtr); 

std::string getDllName(const std::string& str);

std::string getFuncName(const std::string& str);

std::string formatDllFunc(const std::string& str);

size_t make_lookup_tables(std::string moduleName, ULONGLONG remoteBase, PVOID modulePtr, 
                                std::map<std::string, std::set<std::string>> &forwarders_lookup,
                                std::map<ULONGLONG, std::string> &va_lookup
                                );
