cmake_minimum_required ( VERSION 3.12 )
project ( pe_to_shellcode )

# Static CRT for all targets
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# libpeconv
set(PECONV_DIR "${CMAKE_SOURCE_DIR}/libpeconv/libpeconv")
include_directories ( ${PECONV_DIR}/include )
add_subdirectory ( ${PECONV_DIR} )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> )

# pe2shc
set(PE2SHC_DIR "${CMAKE_SOURCE_DIR}/pe2shc")
set(LOADER_DIR "${CMAKE_SOURCE_DIR}/loader_v2")
include_directories ( ${LOADER_DIR} )

add_executable ( pe2shc
    ${PE2SHC_DIR}/main.cpp
    ${PE2SHC_DIR}/resource2.rc
    ${PE2SHC_DIR}/resource.h
)
target_link_libraries ( pe2shc ${PECONV_LIB} )
add_dependencies( pe2shc libpeconv )
target_include_directories(pe2shc PRIVATE ${PE2SHC_DIR})

# runshc
add_executable ( runshc
    ${CMAKE_SOURCE_DIR}/runshc/main.cpp
)
target_link_libraries ( runshc ${PECONV_LIB} )
add_dependencies( runshc libpeconv )

# injector (standalone, no libpeconv)
add_executable ( injector
    ${CMAKE_SOURCE_DIR}/injector/main.cpp
    ${CMAKE_SOURCE_DIR}/injector/util.cpp
    ${CMAKE_SOURCE_DIR}/injector/util.h
)