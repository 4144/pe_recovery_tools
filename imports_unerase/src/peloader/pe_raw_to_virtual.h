#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"

bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size);

// Map raw PE into virtual memory of local process:
bool sections_raw_to_virtual(const BYTE* payload, SIZE_T destBufferSize, BYTE* destAddress);

//set a new image base in headers
bool update_image_base(BYTE* payload, PVOID destImageBase);

BYTE* pe_raw_to_virtual(const BYTE* payload, size_t in_size, size_t &out_size);

// maps PE into memory (raw to virtual)
BYTE* load_pe_module(char *filename, OUT size_t &v_size);
