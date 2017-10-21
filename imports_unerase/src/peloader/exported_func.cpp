#include "exported_func.h"

#include <algorithm>

char easytolower(char in)
{
    if(in<='Z' && in>='A')
    return in-('Z'-'z');
    return in;
}


ExportedFunc::ExportedFunc(DWORD rva, std::string libName, std::string funcName, DWORD funcOrdinal)
{
    this->rva = rva;
    this->libName = ExportedFunc::formatName(libName);
    this->funcName = funcName;
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = false;
}

ExportedFunc::ExportedFunc(DWORD rva, std::string libName, DWORD funcOrdinal)
{
    this->rva = rva;
    this->libName = ExportedFunc::formatName(libName);
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = true;
}

ExportedFunc::ExportedFunc(const ExportedFunc& other)
{
    this->rva = other.rva;
    this->libName = other.libName;
    this->funcName = other.funcName;
    this->funcOrdinal = other.funcOrdinal;
    this->isByOrdinal = other.isByOrdinal;
}

std::string ExportedFunc::formatName(std::string name)
{
    if (name.length() == 0 || name.length() == 0) {
        return "";
    }
    std::transform(name.begin(), name.end(), name.begin(), easytolower);
    return name;
}

std::string ExportedFunc::toString() const
{
    char str[MAX_PATH*2] = { 0 }; //TODO: implement it in a better way
    sprintf(str,"[%x] %s.%s %x", this->rva, this->libName.c_str(), this->funcName.c_str(), this->funcOrdinal);
    return str;
}