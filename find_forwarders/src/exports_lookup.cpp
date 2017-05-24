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
