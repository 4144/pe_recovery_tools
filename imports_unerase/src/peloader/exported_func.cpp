#include "exported_func.h"

#include <algorithm>

char easytolower(char in)
{
    if(in<='Z' && in>='A')
    return in-('Z'-'z');
    return in;
}

std::string exportedFunc::formatName(std::string name)
{
    if (name.length() == 0 || name.length() == 0) {
        return "";
    }
    std::transform(name.begin(), name.end(), name.begin(), easytolower);
    return name;
}
