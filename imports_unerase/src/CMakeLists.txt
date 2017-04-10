cmake_minimum_required (VERSION 2.8)
project (imports_unerase)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (peloader_srcs
	peloader/pe_hdrs_helper.cpp
    peloader/pe_raw_to_virtual.cpp
	peloader/fix_imports.cpp
    peloader/exports_lookup.cpp
)

set (peloader_hdrs
	peloader/pe_hdrs_helper.h
    peloader/pe_raw_to_virtual.h
	peloader/fix_imports.h
    peloader/exports_lookup.h
)
set (srcs
	main.cpp
    ${peloader_srcs}
)

set (hdrs
    ${peloader_hdrs}
)

add_executable (imports_unerase ${hdrs} ${srcs})
