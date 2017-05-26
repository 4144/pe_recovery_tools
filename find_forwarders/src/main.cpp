#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#include <stdio.h>
#include <iostream>

#include "exports_lookup.h"

size_t enum_modules_in_process(DWORD process_id, std::map<ULONGLONG, MODULEENTRY32> &modulesMap)
{
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
    MODULEENTRY32 module_entry = { 0 };
    module_entry.dwSize = sizeof(module_entry);
	
    if (!Module32First(hProcessSnapShot, &module_entry)) {
        printf("[ERROR] Fetching modules failed!\n");
        return 0;
    }
    size_t modules = 1;
    modulesMap[(ULONGLONG) module_entry.modBaseAddr] = module_entry;

    while (Module32Next(hProcessSnapShot, &module_entry)) {
        modulesMap[(ULONGLONG) module_entry.modBaseAddr] = module_entry;
        modules++;
    }

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return modules;
}

bool prepare_mapping(DWORD pid, 
                     std::map<std::string, std::set<std::string>> &forwarders_lookup, 
                     std::map<ULONGLONG, std::string> &va_lookup
                     )
{
    std::map<ULONGLONG, MODULEENTRY32> modulesMap;
    int num = enum_modules_in_process(pid, modulesMap);
    if (num == 0) {
        return false;
    }

    printf("Mapped modules: %d\n", num);
    size_t forwarding_dlls = 0;

    std::map<ULONGLONG, MODULEENTRY32>::iterator itr1;
    for (itr1 = modulesMap.begin(); itr1 != modulesMap.end(); itr1++) {
        size_t v_size = 0;
        BYTE *mappedDLL = load_pe_module(itr1->second.szExePath, v_size);
        if (!mappedDLL) {
            printf("[-] Could not map the DLL: %s\n", itr1->second.szExePath);
            continue;
        }
        ULONGLONG remoteBase = (ULONGLONG) itr1->second.modBaseAddr;
        size_t forwarded_ctr = make_lookup_tables(itr1->second.szExePath, remoteBase, mappedDLL, forwarders_lookup, va_lookup);
        if (forwarded_ctr) {
            forwarding_dlls++;
        }
        VirtualFree(mappedDLL, v_size, MEM_FREE);
    }
    printf("Found forwarding DLLs: %d\n", forwarding_dlls);
    return true;
}

int main(int argc, char *argv[])
{
    ULONGLONG loadBase = 0;
    if (argc < 3) {
        printf("find_forwarders - a tool finding the name of the import (and the forwarders) by it's virtual address\n");
        printf("Args: <PID> <searched_addr>\n");
        printf("PID:\n    (decimal) PID of the target application\n");
        printf("searched_addr:\n    (hexadecimal) VA of the imported function which name we want to retrieve\n");
        system("pause");
        return -1;
    }
    DWORD pid = atoi(argv[1]);
    if (pid == 0) pid = GetCurrentProcessId();
    printf("PID: %d\n", pid);

    ULONGLONG searchedAddr = 0;
    if (sscanf(argv[2],"%llX", &searchedAddr) == 0) {
        sscanf(argv[2],"%#llX", &searchedAddr);
    }

    printf("Searched address: %X\n", searchedAddr);

    std::map<std::string, std::set<std::string>> forwarders_lookup;
    std::map<ULONGLONG, std::string> va_lookup;

    bool isOk = prepare_mapping(pid, forwarders_lookup, va_lookup);
    if (!isOk) {
        printf("[-] Mapping failed.\n");
        system("pause");
        return 0;
    }

    if (va_lookup.find(searchedAddr) != va_lookup.end()) {
        std::string func_name = va_lookup[searchedAddr];
        printf("[+] Found func: %s\n", func_name.c_str());

        std::map<std::string, std::set<std::string>>::iterator fItr = forwarders_lookup.find(func_name);
        if (fItr != forwarders_lookup.end()) {
            printf("[+] Forwarders (%d):\n", fItr->second.size());
            std::set<std::string>::iterator sItr;
            for (sItr = fItr->second.begin(); sItr != fItr->second.end(); sItr++) {
                printf("-> %s\n", sItr->c_str());
            }
        }
    } else {
        printf("[-] Function not found!\n");
    }
    system("pause");
    return 0;
}
