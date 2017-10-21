#include "exported_func.h"

#include <algorithm>

char easytolower(char in)
{
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

ExportedFunc::ExportedFunc(std::string libName, std::string funcName, DWORD funcOrdinal)
{
    this->libName = ExportedFunc::formatName(libName);
    this->funcName = funcName;
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = false;
}

ExportedFunc::ExportedFunc(std::string libName, DWORD funcOrdinal)
{
    this->libName = ExportedFunc::formatName(libName);
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = true;
}

ExportedFunc::ExportedFunc(const ExportedFunc& other)
{
    this->libName = other.libName;
    this->funcName = other.funcName;
    this->funcOrdinal = other.funcOrdinal;
    this->isByOrdinal = other.isByOrdinal;
}

ExportedFunc::ExportedFunc(const std::string &forwarderName)
{
    this->funcName = getFuncName(forwarderName);
    this->libName = getDllName(forwarderName);
    this->isByOrdinal = false;
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
    sprintf(str,"%s.%s %x", this->libName.c_str(), this->funcName.c_str(), this->funcOrdinal);
    return str;
}