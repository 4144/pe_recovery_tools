#include "exports_lookup.h"

#include <algorithm>

size_t forwarderNameLen(BYTE* fPtr)
{
    size_t len = 0;
    while ((*fPtr >= 'a' && *fPtr <= 'z')
            || (*fPtr >= 'A' && *fPtr <= 'Z')
            || (*fPtr >= '0' && *fPtr <= '9')
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

size_t make_ord_lookup_tables(ULONGLONG remoteBase, PVOID modulePtr, 
                                std::map<ULONGLONG, DWORD> &va_to_ord
                                )
{
    size_t forwarded_ctr = 0;

    IMAGE_DATA_DIRECTORY *exportsDir = get_pe_directory((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exportsDir == NULL) return NULL;

    DWORD expAddr = exportsDir->VirtualAddress;
    if (expAddr == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR) modulePtr);

    SIZE_T functCount = exp->NumberOfFunctions;
	DWORD funcsListRVA = exp->AddressOfFunctions;
	DWORD ordBase = exp->Base;

    //go through names:
    for (SIZE_T i = 0; i < functCount; i++) {
		DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
		DWORD ordinal = ordBase + i;
        va_to_ord[(ULONGLONG)funcRVA] = ordinal;
    }
    return functCount - forwarded_ctr;
}


size_t make_lookup_tables(std::string moduleName, ULONGLONG remoteBase, PVOID modulePtr, 
                                std::map<std::string, std::set<std::string>> &forwarders_lookup,
                                std::map<ULONGLONG, std::set<std::string>> &va_to_names,
                                std::map<std::string, ULONGLONG> &name_to_va,
                                std::map<ExportedFunc, std::set<ExportedFunc>> &forwarders_lookup2,
                                std::map<ULONGLONG, std::set<ExportedFunc>> &va_to_func,
                                std::map<ExportedFunc, ULONGLONG> &func_to_va
                                )
{
    std::map<ULONGLONG, DWORD> va_to_ord;
    size_t ord = make_ord_lookup_tables(remoteBase, modulePtr, va_to_ord);

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
        DWORD funcOrd = va_to_ord[(ULONGLONG)funcRVA];
       
        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);
        std::string currFuncName = dllName + "." + name;
        ExportedFunc currFunc(dllName, name, funcOrd);

        currFuncName = formatDllFunc(currFuncName);

        BYTE* fPtr = (BYTE*) modulePtr + (*funcRVA);
        if (forwarderNameLen(fPtr) > 1) {
            std::string forwardedFunc = formatDllFunc((char*)fPtr);
            if (forwardedFunc.length() == 0) {
                continue;
            }

            ExportedFunc forwarder(forwardedFunc);
            forwarders_lookup2[forwarder].insert(currFunc);
            forwarders_lookup[forwardedFunc].insert(currFuncName);

            if (name_to_va[forwardedFunc] != 0) {
                ULONGLONG va = name_to_va[forwardedFunc];
                va_to_names[va].insert(currFuncName);
                name_to_va[currFuncName] = va;

                va_to_func[va].insert(currFunc);
                func_to_va[currFunc] = va;
            }
            forwarded_ctr++;
            continue;
        } else {
            //not forwarded, simple case:
            ULONGLONG va = remoteBase + (*funcRVA);
            va_to_names[va].insert(currFuncName);
            name_to_va[currFuncName] = va;

            va_to_func[va].insert(currFunc);
            func_to_va[currFunc] = va;

            //resolve forwarders of this function (if any):

            std::map<std::string, std::set<std::string>>::iterator fItr = forwarders_lookup.find(currFuncName);
            if (fItr != forwarders_lookup.end()) {
                //printf("[+] Forwarders (%d):\n", fItr->second.size());
                std::set<std::string>::iterator sItr;
                for (sItr = fItr->second.begin(); sItr != fItr->second.end(); sItr++) {
                    //printf("-> %s\n", sItr->c_str());
                    va_to_names[va].insert(*sItr);
                    name_to_va[*sItr] = va;

                    va_to_func[va].insert(currFunc);
                    func_to_va[currFunc] = va;
                }
            }
        }
    }
    return forwarded_ctr;
}
