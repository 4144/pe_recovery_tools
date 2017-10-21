#pragma once

#include <Windows.h>
#include <string>
#include <algorithm>
#include <set>

char easytolower(char in);
std::string getDllName(const std::string& str);
std::string getFuncName(const std::string& str);

class ExportedFunc
{
public:
    static std::string formatName(std::string name);

    std::string libName;
    std::string funcName;
    DWORD funcOrdinal;
    bool isByOrdinal;

    ExportedFunc(const ExportedFunc& other);
    ExportedFunc(std::string libName, std::string funcName, DWORD funcOrdinal);
    ExportedFunc(std::string libName, DWORD funcOrdinal);
    ExportedFunc(const std::string &forwarderName);

    bool operator<(const ExportedFunc& other) const
    {
        int cmp = libName.compare(other.libName);
        if (cmp != 0) {
            return cmp < 0;
        }
        cmp = funcName.compare(other.funcName);
        if (this->funcName.length() != 0 && other.funcName.length() != 0) {
            if (cmp != 0) {
                return cmp < 0;
            }
        }
        return this->funcOrdinal < other.funcOrdinal;
    }

    std::string ExportedFunc::toString() const;
};
