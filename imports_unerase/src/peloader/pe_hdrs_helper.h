#pragma once
#include <Windows.h>

BYTE* get_nt_hrds(const BYTE *pe_buffer);
IMAGE_NT_HEADERS32* get_nt_hrds32(const BYTE *pe_buffer);
IMAGE_NT_HEADERS64* get_nt_hrds64(const BYTE *pe_buffer);

IMAGE_DATA_DIRECTORY* get_pe_directory(const BYTE* pe_buffer, DWORD dir_id);
bool is64bit(const BYTE *pe_buffer);