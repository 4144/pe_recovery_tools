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
        if (this->rva != other.rva) {
            this->rva > other.rva;
        }
        int cmp = libName.compare(other.libName);
        if (cmp != 0) {
            return cmp < 0;
        }
        if (isByOrdinal) {
            this->funcOrdinal < other.funcOrdinal;
        }
        cmp = funcName.compare(other.funcName);
        if (cmp != 0) {
            return cmp < 0;
        }
        this->funcOrdinal < other.funcOrdinal;
    }

    std::string ExportedFunc::toString() const;
};
