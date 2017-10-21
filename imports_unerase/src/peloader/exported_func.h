#pragma once

#include <Windows.h>
#include <string>
#include <algorithm>
#include <set>

char easytolower(char in);

class ExportedFunc
{
public:
    static std::string formatName(std::string name);

    DWORD rva;
    std::string libName;
    std::string funcName;
    DWORD funcOrdinal;
    bool isByOrdinal;

    ExportedFunc(DWORD rva, std::string libName, std::string funcName, DWORD funcOrdinal);
    ExportedFunc(DWORD rva, std::string libName, DWORD funcOrdinal);
    ExportedFunc(const ExportedFunc& other);

    bool operator<(const ExportedFunc& other) const
    {
        if (libName == other.libName) {
            return (funcName > other.funcName);
        }
         return (libName > other.libName);
    }

    std::string ExportedFunc::toString() const;
};
