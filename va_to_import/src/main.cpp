#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#include <map>
#include <iostream>

#include "peloader/pe_hdrs_helper.h"

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

char* get_exported_func_name(PVOID modulePtr, ULONGLONG searchedRVA)
{
    IMAGE_DATA_DIRECTORY *exportsDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exportsDir == NULL) return NULL;

    DWORD expAddr = exportsDir->VirtualAddress;
    if (expAddr == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR) modulePtr);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*) modulePtr + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + (*nameIndex) * sizeof(DWORD));

        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);
        if (searchedRVA == (*funcRVA)) {
            return name;
        }
    }
    //function not found
    return NULL;
}

void log_info(FILE *f, MODULEENTRY32 &module_entry)
{
	if (f == NULL) return;
    BYTE* mod_end = module_entry.modBaseAddr + module_entry.modBaseSize;
    fprintf(f, "%p,%p,%s\n", module_entry.modBaseAddr, mod_end, module_entry.szModule);
    fflush(f);
}

int main(int argc, char *argv[])
{
    ULONGLONG loadBase = 0;
    if (argc < 2) {
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

	char filename[MAX_PATH] = { 0 };
	sprintf(filename, "PID_%d_modules.txt", pid);
	FILE *f = fopen(filename, "w");

    ULONGLONG searchedAddr = 0;
	if (argc >= 3) {
		if (sscanf(argv[2],"%llX", &searchedAddr) == 0) {
			sscanf(argv[2],"%#llX", &searchedAddr);
		}
	}
    std::map<ULONGLONG, MODULEENTRY32> modulesMap;
    int num = enum_modules_in_process(pid, modulesMap);

    printf("Mapped modules: %d\n", num);
	std::map<ULONGLONG, MODULEENTRY32>::iterator itr1;
	for (itr1 = modulesMap.begin(); itr1 != modulesMap.end(); itr1++) {
		log_info(f,itr1->second);
	}
	if (f) {
		printf("Logged modules to: %s\n", filename);
		fclose(f);
		f = NULL;
	}
	if (searchedAddr == 0) {
		system("pause");
		return 0;
	}
	printf("---\n");
    std::map<ULONGLONG, MODULEENTRY32>::iterator lastEl = modulesMap.lower_bound(searchedAddr);
    HMODULE foundMod = NULL;
    for (itr1 = modulesMap.begin(); itr1 != lastEl; itr1++) {
        ULONGLONG begin = itr1->first;
        ULONGLONG end = itr1->second.modBaseSize + begin;
        
        if (searchedAddr >= begin && searchedAddr < end) {
            ULONGLONG searchedRVA = searchedAddr - begin;
			printf("[+] Address found:\n");
            printf("Module: %s\n", itr1->second.szExePath);

            foundMod = LoadLibraryA(itr1->second.szExePath);
            if (foundMod == NULL) {
                printf("Loading module failed!\n");
                break;
            }

			char *func_name = get_exported_func_name(foundMod, searchedRVA);
            if (func_name) {
				printf("Function: %s\n", func_name);
				printf("RVA: %llX\n", searchedRVA);
			} else {
				printf("Function not found!\n");
			}
            break;
        }
    }
    system("pause");
    return 0;
}