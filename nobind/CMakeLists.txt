cmake_minimum_required(VERSION 3.28)
#
project(NOBIND VERSION 1.0)
#
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
#
configure_file(nobind.h.in nobind.h)
#
add_library(nobind SHARED landlocked.c nobind.c)
if(DEBUG)
    message("NOTICE: debug enabled")
    target_compile_definitions(nobind PUBLIC -DLANDLOCKED_DEBUG)
else()
    message("NOTICE: debug disabled")
endif()
