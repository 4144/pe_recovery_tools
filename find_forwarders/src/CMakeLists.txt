cmake_minimum_required (VERSION 2.8)
project (find_forwarders)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (peloader_srcs
	peloader/pe_hdrs_helper.cpp
    peloader/pe_raw_to_virtual.cpp
)

set (peloader_hdrs
	peloader/pe_hdrs_helper.h
    peloader/pe_raw_to_virtual.h
)
set (srcs
	main.cpp
	exports_lookup.cpp
	${peloader_srcs}
)

set (hdrs
	exports_lookup.h
	${peloader_hdrs}
)

add_executable (find_forwarders ${hdrs} ${srcs})
