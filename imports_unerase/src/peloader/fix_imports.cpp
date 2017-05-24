#include "fix_imports.h"
#include <algorithm>

#define MIN_DLL_LEN 5

inline size_t offset(const char* buf, size_t len, const char* str)
{
    return std::search(buf, buf + len, str, str + strlen(str)) - buf;
}

LPVOID search_name(std::string name, const char* modulePtr, size_t moduleSize)
{
    size_t o = offset(modulePtr, moduleSize, name.c_str());
    if (o < moduleSize) {
       return (LPVOID)(modulePtr + o);
    }
    return NULL;
}

bool fillImportNames32(IMAGE_IMPORT_DESCRIPTOR* lib_desc, LPVOID modulePtr, size_t moduleSize,
        std::map<ULONGLONG, std::string> &addr_to_func)
{
    if (lib_desc == NULL) return false;

    DWORD call_via = lib_desc->FirstThunk;
    DWORD thunk_addr = lib_desc->OriginalFirstThunk; // warning: it can be NULL!
    bool is_single_thunk = false;
    
    if (call_via == 0) return false;

    if (thunk_addr == 0) {
        thunk_addr = call_via;
        is_single_thunk = true;
    }

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
        std::string found_name = addr_to_func[searchedAddr];
        if (found_name.length() == 0) {
            printf("[-] Function not found: %X\n", searchedAddr);
            call_via += sizeof(DWORD);
            thunk_addr += sizeof(DWORD);
            continue;
        }
        printf("[+] %s\n", found_name.c_str());

        //can I save the name in the original thunk?
        if (is_single_thunk || *thunk_val != *call_via_val) {
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
            if (validate_ptr(modulePtr, moduleSize, func_name, found_name.length()) == true) {
                memcpy(func_name, found_name.c_str(), found_name.length());
                printf("[+] Saved\n");
            } else {
                // try to find the offset to the name in the module:
                BYTE* found_ptr = (BYTE*) search_name(found_name, (const char*) modulePtr, moduleSize);
                if (found_ptr) {
                    DWORD offset = static_cast<DWORD>((ULONGLONG)found_ptr - (ULONGLONG)modulePtr);
                    printf("[*] Found the name at: %llx\n", static_cast<ULONGLONG>(offset));
                    offset -= sizeof(WORD);
                    //TODO: validate more...

                    memcpy(call_via_ptr, &offset, sizeof(DWORD)); 
                    //printf("[*] Saved offset as thunk val: %llx\n", static_cast<ULONGLONG>(offset));
                } else {
                    printf("[-] Cannot save! Invalid pointer to the function name!\n");
                    //TODO: create a new section to store the names
                }
            }
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
                        coveredCount++;
                    }
                }
            }
        }
    }
    return coveredCount;
}

bool fixImports(PVOID modulePtr, size_t moduleSize, std::map<ULONGLONG, std::set<std::string>> va_to_names)
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
        if (!validate_ptr(modulePtr, moduleSize, lib_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            printf("[-] Invalid descriptor pointer!\n");
            return false;
        }
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) {
            break;
        }

        printf("Imported Lib: %x : %x : %x\n", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);

        LPSTR name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
        if (!validate_ptr(modulePtr, moduleSize, name_ptr, sizeof(char) * MIN_DLL_LEN)) {
            printf("[-] Invalid pointer to the name!\n");
            return false;
        }
        std::string lib_name = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk; // warning: it can be NULL!
        std::set<ULONGLONG> addresses;
        if (!is64) {
            findAddressesToFill32(call_via, thunk_addr, modulePtr, addresses);
        } else {
            printf("[-] Support for 64 bit PE is not implemented yet!\n");
            return false;
        }
        if (lib_name.length() == 0) {
            printf("erased DLL name\n");
            lib_name = findDllName(addresses, va_to_names);
            if (lib_name.length() != 0) {
                std::string found_name = lib_name + ".dll";
                name_ptr = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
                if (!validate_ptr(modulePtr, moduleSize, name_ptr, found_name.length())) {
                    printf("[-] Invalid pointer to the name!\n");
                    return false;
                }
                memcpy(name_ptr, found_name.c_str(), found_name.length());
            }
        } else {
            lib_name = getDllName(lib_name);
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
            if (!fillImportNames32(lib_desc, modulePtr, moduleSize, addr_to_func)) {
                return false;
            }
        }
    }
    printf("---------\n");
    return true;
}
