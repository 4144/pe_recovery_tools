#pragma once

#include <Windows.h>
#include <string>
#include <algorithm>

char easytolower(char in);

class exportedFunc
{
public:
    DWORD rva;
    std::string libName;
    std::string funcName;
    DWORD funcOrdinal;

    static std::string formatName(std::string name);
};
