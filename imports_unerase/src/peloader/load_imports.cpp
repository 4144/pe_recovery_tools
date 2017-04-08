#include "load_imports.h"

HMODULE findInModulesMap(std::map<ULONGLONG, MODULEENTRY32> &modulesMap, ULONGLONG &dllBase, ULONGLONG searchedAddr)
{
    std::map<ULONGLONG, MODULEENTRY32>::iterator lastEl = modulesMap.lower_bound(searchedAddr);
    std::map<ULONGLONG, MODULEENTRY32>::iterator itr1;
    HMODULE foundMod = NULL;
    for (itr1 = modulesMap.begin(); itr1 != lastEl; itr1++) {
        ULONGLONG begin = itr1->first;
        ULONGLONG end = itr1->second.modBaseSize + begin;
        
        if (searchedAddr >= begin && searchedAddr < end) {
            ULONGLONG searchedRVA = searchedAddr - begin;
            dllBase = begin;
            printf("Found address in the module: %s\n", itr1->second.szExePath);
            printf("Function RVA: %llX\n", searchedRVA);
            return LoadLibraryA(itr1->second.szExePath);
        }
    }
    dllBase = NULL;
    return NULL;
}

HMODULE findDll32(std::map<ULONGLONG, MODULEENTRY32> &modulesMap, ULONGLONG &dllBase, LPVOID modulePtr, DWORD call_via)
{
    LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
    if (call_via_ptr == NULL) {
        return NULL;
    }
    printf("call_via_ptr: %p", call_via_ptr);
    DWORD *call_via_val = (DWORD*)call_via_ptr;
    DWORD searchedAddr = (*call_via_val);

    printf("Searched Addr: %X\n", searchedAddr);
    if (searchedAddr == 0) {
        return NULL;
    }
    return findInModulesMap(modulesMap, dllBase, (ULONGLONG)searchedAddr);
}

bool getModuleShortName(char* fullName, char* outBuf)
{
    if (fullName == NULL) return false;

    int fullLen = strlen(fullName);
    int i = fullLen - 1;
    for (; i >= 0; i--) {
        if (fullName[i] == '\\' || fullName[i] == '/') {
            i++;
            break;
        }
    }
    if (i >= fullLen - 1) return false;
    memcpy(outBuf, &fullName[i], fullLen - i);
    return true;
}

char* get_exported_func(PVOID modulePtr, ULONGLONG searchedRVA)
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
            printf("Name: %s\n", name);
            return name;
        }
    }
    //function not found
    return NULL;
}

bool solve_imported_funcs_b32(HMODULE dllHndl, ULONGLONG dllBase, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr)
{
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        DWORD *thunk_val = (DWORD*)thunk_ptr;
        DWORD *call_via_val = (DWORD*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return false;
        }
        ULONGLONG searchedAddr = ULONGLONG(*call_via_val) - dllBase;
        char* found_name = get_exported_func(dllHndl, searchedAddr);
        if (found_name == NULL) {
            printf("[-] Function not found: %X\n", searchedAddr);
            //TODO: check forwarded
            call_via += sizeof(DWORD);
            thunk_addr += sizeof(DWORD);
            continue;
        }
        printf("[+] %s\n", found_name);

        //can I save the name in the original thunk?
        if (*thunk_val != *call_via_val) {
            IMAGE_THUNK_DATA32* desc = (IMAGE_THUNK_DATA32*) thunk_ptr;
            if (desc->u1.Function == NULL) break;

            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG) modulePtr + desc->u1.AddressOfData);
            if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                printf("Imports by ordinals are not supported!\n");
                call_via += sizeof(DWORD);
                thunk_addr += sizeof(DWORD);
                continue;
            }
            LPSTR func_name = by_name->Name;
            memcpy(func_name, found_name, strlen(found_name)); 
        }
        call_via += sizeof(DWORD);
        thunk_addr += sizeof(DWORD);
    } while (true);
    return true;
}

//fills handles of mapped pe file
bool fix_imports(PVOID modulePtr, std::map<ULONGLONG, MODULEENTRY32> modulesMap)
{
    bool is64 = is64bit((BYTE*)modulePtr);

    IMAGE_DATA_DIRECTORY *importsDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    DWORD maxSize = importsDir->Size;
    DWORD impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    DWORD parsedSize = 0;

    printf("---IMP---\n");
    while (parsedSize < maxSize) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }

        printf("Imported Lib: %x : %x : %x\n", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        if (strlen(lib_name) == 0) {
            printf("erased DLL name\n");
        } else {
             printf("name: %s\n", lib_name);
        }

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk; // warning: it can be NULL!
        ULONGLONG dllBase = 0;
        HMODULE dllHndl = NULL; 
        if (!is64) {
            dllHndl = findDll32(modulesMap, dllBase, modulePtr, call_via);
        } else {
            printf("PE 64bit not supported yet!\n");
        }
        if (dllHndl == NULL) {
            printf("[ERROR] Cannot find DLL!\n");
            return false;
        }
        char dllFullName[MAX_PATH] = {0};
        GetModuleFileNameA(dllHndl, dllFullName, MAX_PATH);
        printf("DLL: %s\n", dllFullName);
        if (getModuleShortName(dllFullName, lib_name)) {
            printf("[+]\n");
        }
        if (!is64) {
            printf("32 bit import\n");
            solve_imported_funcs_b32(dllHndl, dllBase, call_via, thunk_addr, modulePtr);
        }
    }
    printf("---------\n");
    return true;
}
