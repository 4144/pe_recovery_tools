#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <map>

#include "pe_hdrs_helper.h"
#include "exports_lookup.h"

bool fixImports(PVOID modulePtr,
    std::map<std::string,std::set<std::string>> &forwarders_lookup, 
    std::map<ULONGLONG, std::set<std::string>> va_to_names
    );
