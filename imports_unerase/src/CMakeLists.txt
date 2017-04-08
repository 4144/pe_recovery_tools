cmake_minimum_required (VERSION 2.8)
project (imports_unerase)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (peloader_srcs
	peloader/pe_hdrs_helper.cpp
	peloader/load_imports.cpp
	peloader/sysutil.cpp
)

set (peloader_hdrs
	peloader/pe_hdrs_helper.h
	peloader/load_imports.h
	peloader/sysutil.h
)
set (srcs
	main.cpp
    ${peloader_srcs}
)

set (hdrs
    ${peloader_hdrs}
)

add_executable (imports_unerase ${hdrs} ${srcs})
