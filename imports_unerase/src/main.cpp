#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#include <map>
#include <iostream>

#include "peloader/pe_hdrs_helper.h"
#include "peloader/load_imports.h"

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

void find_function_at_addr(std::map<ULONGLONG, MODULEENTRY32> modulesMap, ULONGLONG searchedAddr)
{
    std::map<ULONGLONG, MODULEENTRY32>::iterator lastEl = modulesMap.lower_bound(searchedAddr);
    std::map<ULONGLONG, MODULEENTRY32>::iterator itr1;
    HMODULE foundMod = NULL;
    for (itr1 = modulesMap.begin(); itr1 != lastEl; itr1++) {
        ULONGLONG begin = itr1->first;
        ULONGLONG end = itr1->second.modBaseSize + begin;
        
        if (searchedAddr >= begin && searchedAddr < end) {
            ULONGLONG searchedRVA = searchedAddr - begin;

            printf("Found address in the module: %s\n", itr1->second.szExePath);
            printf("Function RVA: %llX\n", searchedRVA);

            foundMod = LoadLibraryA(itr1->second.szExePath);
            if (foundMod == NULL) {
                printf("Loading module failed!\n");
                break;
            }
            get_exported_func(foundMod, searchedRVA);
            break;
        }
    }
}

BYTE* load_file(char *filename, size_t &size)
{
    if (filename == NULL) return NULL;

    printf("filename: %s\n", filename);
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Cannot open file!\n");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    printf("size = %d\n", size);
    BYTE* in_buf = (BYTE*) VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    fseek(f, 0, SEEK_SET);
    fread(in_buf, 1, size, f);
    fclose(f);

    return in_buf;
}

int main(int argc, char *argv[])
{
    ULONGLONG loadBase = 0;
    if (argc < 3) {
        printf("A tool to recover erased imports\n");
        printf("Required args: <PID> <dumped_file>\n---\n");
        printf("PID: (decimal) PID of the target application\n");
        printf("dumped_file: a module dumped from the app with the given PID (in Virtual format)\n");
        printf("---\n");
        system("pause");
        return -1;
    }
    
    char *out_filename = "out.bin";

    DWORD pid = atoi(argv[1]);
    
    if (pid == 0) pid = GetCurrentProcessId();
    printf("PID: %d\n", pid);

    std::map<ULONGLONG, MODULEENTRY32> modulesMap;
    int num = enum_modules_in_process(pid, modulesMap);
    if (num == 0) {
        printf("[ERROR] Cannot fetch modules from the process with PID: %d\n", pid);
        system("pause");
        return -1;
    }
    size_t size = 0;
    BYTE* buffer = load_file(argv[2], size);
    if (buffer == NULL) {
        printf("[ERROR] Cannot load the file!\n");
        system("pause");
        return -1;
    }
    
    fix_imports(buffer, modulesMap);
    FILE *fout = fopen(out_filename, "wb");
    fwrite(buffer, 1, size, fout);
    fclose(fout);
    VirtualFree(buffer, size, MEM_FREE);
    printf("[+] Saved output to: %s\n", out_filename);
    system("pause");
    return 0;
}