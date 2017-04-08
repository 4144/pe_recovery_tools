cmake_minimum_required (VERSION 2.8)
project (va_to_import)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (peloader_srcs
	peloader/pe_hdrs_helper.cpp
)

set (peloader_hdrs
	peloader/pe_hdrs_helper.h
)
set (srcs
	main.cpp
	${peloader_srcs}
)

set (hdrs
	${peloader_hdrs}
)

add_executable (va_to_import ${hdrs} ${srcs})
