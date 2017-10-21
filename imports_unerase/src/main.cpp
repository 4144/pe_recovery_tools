#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#include <map>
#include <iostream>

#include "peloader/pe_hdrs_helper.h"
#include "peloader/pe_raw_to_virtual.h"
#include "peloader/fix_imports.h"

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

void print_va_to_func(std::map<ULONGLONG, std::set<ExportedFunc>> &va_to_func)
{
    static FILE *fp = fopen("va_to_func.txt", "a+");

    std::map<ULONGLONG, std::set<ExportedFunc>>::iterator mItr;
    for (mItr = va_to_func.begin(); mItr != va_to_func.end(); mItr++) {
        ULONGLONG va = mItr->first;
        std::set<ExportedFunc> &funcSet = mItr->second;
        std::set<ExportedFunc>::iterator sItr;
        for (sItr = funcSet.begin(); sItr != funcSet.end(); sItr++) {
            const ExportedFunc &func = *sItr;
            std::string str = func.toString();
            if (fp) {
                fprintf(fp, "[%llx] %s\n", va, str.c_str());
                fflush(fp);
            }
        }
    }
}

void print_func_to_rva(std::map<ExportedFunc, ULONGLONG> &func_to_va)
{
    static FILE *fp = fopen("func_to_rva.txt", "a+");

    std::map<ExportedFunc, ULONGLONG>::iterator mItr;
    for (mItr = func_to_va.begin(); mItr != func_to_va.end(); mItr++) {
        const ExportedFunc &func = mItr->first;
        const ULONGLONG va = mItr->second;
        std::string str = func.toString();

        if (fp) {
            fprintf(fp, "[%llx] %s\n", va, str.c_str());
            fflush(fp);
        }
    }
}

void print_forwarders(std::map<ExportedFunc, std::set<ExportedFunc>> &forwarders_lookup2)
{
    static FILE *fp = fopen("forwarders.txt", "a+");

    std::map<ExportedFunc, std::set<ExportedFunc>>::iterator mItr;
    for (mItr = forwarders_lookup2.begin(); mItr != forwarders_lookup2.end(); mItr++) {
        const ExportedFunc &func = mItr->first;

        const std::set<ExportedFunc> &fwdSet = mItr->second;
        std::string str = func.toString();
        if (fp) {
            fprintf(fp, "> %s : %d\n", str.c_str(), fwdSet.size());
            fflush(fp);
        }
        std::set<ExportedFunc>::iterator sItr;
        for (sItr = fwdSet.begin(); sItr != fwdSet.end(); sItr++) {
            const ExportedFunc &fwdFunc = *sItr;
            std::string fwdStr = fwdFunc.toString();
            fprintf(fp, "- %s\n", fwdStr.c_str());
        }
    }
}


bool prepare_mapping(DWORD pid, std::map<ULONGLONG, std::set<ExportedFunc>> &va_to_func)
{
    std::map<std::string, std::set<std::string>> forwarders_lookup;
    std::map<std::string, ULONGLONG> name_to_va;

    std::map<ULONGLONG, MODULEENTRY32> modulesMap;
    int num = enum_modules_in_process(pid, modulesMap);
    if (num == 0) {
        return false;
    }

    printf("Mapped modules: %d\n", num);
    size_t forwarding_dlls = 0;

    std::map<ExportedFunc, std::set<ExportedFunc>> forwarders_lookup2; //TEST
    std::map<ExportedFunc, ULONGLONG> func_to_va; //TEST

    std::map<ULONGLONG, MODULEENTRY32>::iterator itr1;
    for (itr1 = modulesMap.begin(); itr1 != modulesMap.end(); itr1++) {
        size_t v_size = 0;
        BYTE *mappedDLL = load_pe_module(itr1->second.szExePath, v_size);
        if (!mappedDLL) {
            printf("[-] Could not map the DLL: %s\n", itr1->second.szExePath);
            continue;
        }
        ULONGLONG remoteBase = (ULONGLONG) itr1->second.modBaseAddr;

        size_t forwarded_ctr = make_lookup_tables(itr1->second.szExePath, remoteBase, mappedDLL, forwarders_lookup2, va_to_func, func_to_va);
        if (forwarded_ctr) {
            forwarding_dlls++;
        }
        VirtualFree(mappedDLL, v_size, MEM_FREE);
    }
    print_va_to_func(va_to_func); //TEST
    print_func_to_rva(func_to_va); //TEST
    print_forwarders(forwarders_lookup2); //TEST
    printf("Found forwarding DLLs: %d\n", forwarding_dlls);
    return true;
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
    char *default_out_file = "out.bin";
    char *version = "0.1.8";
    ULONGLONG loadBase = 0;
    if (argc < 3) {
        printf("[Imports_Unerase v%s]\n", version);
        printf("A tool to recover erased imports\n---\n");
        printf("Args: <PID> <dumped_file> [out_file*]\n");
        printf("PID:\n\t(decimal) PID of the target application\n");
        printf("dumped_file:\n\ta module dumped from the app with the given PID (virtual format)\n");
        printf("out_file:\n\tname of the output file (default: %s)\n", default_out_file);
        printf("* - optional\n");
        printf("---\n");
        system("pause");
        return -1;
    }

    char *out_filename = (argc > 3) ? argv[3] : default_out_file;

    DWORD pid = atoi(argv[1]);
    
    if (pid == 0) pid = GetCurrentProcessId();
    printf("PID: %d\n", pid);

    std::map<ULONGLONG, std::set<ExportedFunc>> va_to_func;
    bool isOk = prepare_mapping(pid, va_to_func);
    if (!isOk) {
        printf("[-] Mapping failed.\n");
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

    if (fixImports(buffer, size, va_to_func) == false) {
        printf("[ERROR] Cannot reconstruct imports!\n");
        system("pause");
        return -1;

    }
    FILE *fout = fopen(out_filename, "wb");
    if (fout) {
        fwrite(buffer, 1, size, fout);
        fclose(fout);
        printf("[+] Saved output to: %s\n", out_filename);
    }
    VirtualFree(buffer, size, MEM_FREE);
    
    system("pause");
    return 0;
}
