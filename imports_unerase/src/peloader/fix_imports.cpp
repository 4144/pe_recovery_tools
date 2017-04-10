#include "fix_imports.h"
#include <algorithm>

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
    IMAGE_DATA_DIRECTORY *exportsDir = get_pe_directory((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
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

bool fillImportNames32(DWORD call_via, DWORD thunk_addr, LPVOID modulePtr, 
                              std::map<ULONGLONG, std::string> &addr_to_func)
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
        ULONGLONG searchedAddr = ULONGLONG(*call_via_val);
        std::string found_name = addr_to_func[searchedAddr];
        if (found_name.length() == 0) {
            printf("[-] Function not found: %X\n", searchedAddr);
            //TODO: check forwarded
            call_via += sizeof(DWORD);
            thunk_addr += sizeof(DWORD);
            continue;
        }
        printf("[+] %s\n", found_name.c_str());

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
            memcpy(func_name, found_name.c_str(), found_name.length()); 
        }
        call_via += sizeof(DWORD);
        thunk_addr += sizeof(DWORD);
    } while (true);
    return true;
}

size_t findAddressesToFill32(DWORD call_via, DWORD thunk_addr, LPVOID modulePtr, OUT std::set<ULONGLONG> &addresses)
{
    size_t addrCounter = 0;
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        DWORD *thunk_val = (DWORD*)thunk_ptr;
        DWORD *call_via_val = (DWORD*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            break;
        }
        ULONGLONG searchedAddr = ULONGLONG(*call_via_val);
        addresses.insert(searchedAddr);
        addrCounter++;
        //---
        call_via += sizeof(DWORD);
        thunk_addr += sizeof(DWORD);
    } while (true);

    return addrCounter;
}

std::string findDllName(std::set<ULONGLONG> &addresses, std::map<ULONGLONG, std::set<std::string>> &va_to_names)
{
    std::set<std::string> dllNames;
    bool isFresh = true;

    std::set<ULONGLONG>::iterator addrItr;
    for (addrItr = addresses.begin(); addrItr != addresses.end(); addrItr++) {
        ULONGLONG searchedAddr = *addrItr;
        //---
        std::map<ULONGLONG, std::set<std::string>>::iterator fItr1 = va_to_names.find(searchedAddr);
        
        if (fItr1 != va_to_names.end()) {
            std::set<std::string> currDllNames;

            for (std::set<std::string>::iterator strItr = fItr1->second.begin(); 
                strItr != fItr1->second.end(); 
                strItr++)
            {
                std::string dll_name = getDllName(*strItr);

                std::string imp_dll_name = getDllName(*strItr);
                currDllNames.insert(imp_dll_name);
            }

            //printf("> %s\n", strItr->c_str());
            if (!isFresh) {
                std::set<std::string> resultSet;
                std::set_intersection(dllNames.begin(), dllNames.end(),
                    currDllNames.begin(), currDllNames.end(),
                    std::inserter(resultSet, resultSet.begin()));
                dllNames = resultSet;
            } else {
                dllNames = currDllNames;
            }
        }
        //---
    }
    if (dllNames.size() > 0) {
        return *(dllNames.begin());
    }
    return "";
}

size_t mapAddressesToFunctions(std::set<ULONGLONG> &addresses, 
                               std::string coveringDll, 
                               std::map<ULONGLONG, std::set<std::string>> &va_to_names, 
                               OUT std::map<ULONGLONG, std::string> &addr_to_func
                               )
{
    size_t coveredCount = 0;
    std::set<ULONGLONG>::iterator addrItr;
    for (addrItr = addresses.begin(); addrItr != addresses.end(); addrItr++) {

        ULONGLONG searchedAddr = *addrItr;
        //---
        std::map<ULONGLONG, std::set<std::string>>::iterator fItr1 = va_to_names.find(searchedAddr);
        
        if (fItr1 != va_to_names.end()) {
            std::set<std::string> currDllNames;

            for (std::set<std::string>::iterator strItr = fItr1->second.begin(); 
                strItr != fItr1->second.end(); 
                strItr++)
            {
                std::string dll_name = getDllName(*strItr);
                if (dll_name == coveringDll) {
                    std::string funcName = getFuncName(*strItr);

                    if (addr_to_func.find(searchedAddr) != addr_to_func.end()) {
                        //it already have some function filled, but we will choose the one with the shorter name:
                        if (addr_to_func[searchedAddr].length() > funcName.length()) {
                            addr_to_func[searchedAddr] = funcName;
                        }
                    } else {
                        // it does not have any function filled, so just put the current one:
                        addr_to_func[searchedAddr] = funcName;
                    }
                    coveredCount++;
                }
            }
        }
    }
    return coveredCount;
}

//fills handles of mapped pe file
bool fixImports(PVOID modulePtr, 
                 std::map<std::string,std::set<std::string>> &forwarders_lookup, 
                 std::map<ULONGLONG, std::set<std::string>> va_to_names
                 )
{
    bool is64 = is64bit((BYTE*)modulePtr);

    IMAGE_DATA_DIRECTORY *importsDir = get_pe_directory((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
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

        std::string lib_name = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk; // warning: it can be NULL!
        std::set<ULONGLONG> addresses;
        if (!is64) {
            findAddressesToFill32(call_via, thunk_addr, modulePtr, addresses);
        }
        if (lib_name.length() == 0) {
            printf("erased DLL name\n");
            lib_name = findDllName(addresses, va_to_names);
            if (lib_name.length() != 0) {
                std::string found_name = lib_name + ".dll";
                char *name_ptr = (char*)((ULONGLONG)modulePtr + lib_desc->Name);
                //TODO: validate the pointer
                memcpy(name_ptr,  found_name.c_str(), found_name.length());
            }
        }
        
        if (lib_name.length() == 0) {
            printf("[ERROR] Cannot find DLL!\n");
            return false;
        }
        printf("# %s\n", lib_name.c_str());
        OUT std::map<ULONGLONG, std::string> addr_to_func;
        size_t coveredCount = mapAddressesToFunctions(addresses, lib_name, va_to_names, addr_to_func); 
        if (coveredCount != addresses.size()) {
            printf("[-] Not all addresses are covered!\n");
        } else {
            printf("All covered!\n");
        }
        if (!is64) {
            printf("32 bit import\n");
            fillImportNames32(call_via, thunk_addr, modulePtr, addr_to_func);
        }
    }
    printf("---------\n");
    return true;
}
