#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>
#include <string>
#include <map>
#include <set>
#include <algorithm>

#include "peloader/pe_hdrs_helper.h"
#include "peloader/pe_raw_to_virtual.h"

size_t enum_modules_in_process(DWORD process_id, std::map<ULONGLONG, MODULEENTRY32> &modulesMap)
{
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, process_id);
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

size_t forwarderNameLen(BYTE* fPtr)
{
    size_t len = 0;
    while ((*fPtr >= 'a' && *fPtr <= 'z')
            || (*fPtr >= 'A' && *fPtr <= 'Z')
            || (*fPtr == '.')
            || (*fPtr == '_') 
            || (*fPtr == '-'))
    {
        len++;
        fPtr++;
    }
    if (*fPtr == '\0') {
        return len;
    }
    return 0;
}

char easytolower(char in){
    if(in<='Z' && in>='A')
    return in-('Z'-'z');
    return in;
}

std::string getDllName(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t found = str.find_last_of("/\\");
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(found+1, ext - (found+1));
    std::transform(name.begin(), name.end(), name.begin(), easytolower);
    return name;
}

std::string getFuncName(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(ext+1, len - (ext+1));
    return name;
}

std::string formatDllFunc(const std::string& str)
{
    std::string dllName = getDllName(str);
    std::string funcName = getFuncName(str);
    if (dllName.length() == 0 || funcName.length() == 0) {
        return "";
    }
    std::transform(dllName.begin(), dllName.end(), dllName.begin(), easytolower);
    return dllName + "." + funcName;
}

size_t make_lookup_tables(std::string moduleName, ULONGLONG remoteBase, PVOID modulePtr, 
                                std::map<std::string, std::set<std::string>> &forwarders_lookup,
                                std::map<ULONGLONG, std::string> &va_lookup
                                )
{
    std::string dllName = getDllName(moduleName);
    size_t forwarded_ctr = 0;

    IMAGE_DATA_DIRECTORY *exportsDir = get_pe_directory((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exportsDir == NULL) return NULL;

    DWORD expAddr = exportsDir->VirtualAddress;
    if (expAddr == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR) modulePtr);
    SIZE_T namesCount = exp->NumberOfNames;

    std::map<DWORD, char*> rva_to_name;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*) modulePtr + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + (*nameIndex) * sizeof(DWORD));
       
        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);
        std::string currFuncName = dllName + "." + name;
        currFuncName = formatDllFunc(currFuncName);

        BYTE* fPtr = (BYTE*) modulePtr + (*funcRVA);
        if (forwarderNameLen(fPtr) > 1) {

            std::string forwardedFunc = formatDllFunc((char*)fPtr);
            if (forwardedFunc.length() == 0) {
                continue;
            }
            forwarders_lookup[forwardedFunc].insert(currFuncName);
            forwarded_ctr++;
            continue;
        }
        va_lookup[remoteBase + (*funcRVA)] = currFuncName;
    }
    return forwarded_ctr;
}

BYTE* map_pe(char *filename, size_t &v_size)
{
    HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(file == INVALID_HANDLE_VALUE) return NULL;

    HANDLE mapping  = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) return NULL;

    BYTE *mappedDLL = NULL;
    BYTE *dllRawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (dllRawData != NULL) {
        size_t r_size = GetFileSize(file, 0);
        mappedDLL = pe_raw_to_virtual(dllRawData, r_size, v_size);
        UnmapViewOfFile(dllRawData);
    }
    CloseHandle(mapping);
    CloseHandle(file);
    return mappedDLL;
}

int main(int argc, char *argv[])
{
    ULONGLONG loadBase = 0;
    if (argc < 3) {
        printf("VA_to_Import - a tool finding the name of the import by it's virtual address\n");
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

    std::map<ULONGLONG, MODULEENTRY32> modulesMap;
    int num = enum_modules_in_process(pid, modulesMap);

    printf("Mapped modules: %d\n", num);

    std::map<std::string, std::set<std::string>> forwarders_lookup;
    std::map<ULONGLONG, std::string> va_lookup;

    std::map<ULONGLONG, MODULEENTRY32>::iterator itr1;
    size_t forwarding_dlls = 0;
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
    printf("[+] Mapping done.\n");

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
