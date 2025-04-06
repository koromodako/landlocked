cmake_minimum_required(VERSION 3.28)
#
project(NOCONNECT VERSION 1.0)
#
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
#
configure_file(noconnect.h.in noconnect.h)
#
add_library(noconnect SHARED landlocked.c noconnect.c)
if(DEBUG)
    message("NOTICE: debug enabled")
    target_compile_definitions(noconnect PUBLIC -DLANDLOCKED_DEBUG)
else()
    message("NOTICE: debug disabled")
endif()
if(RANDOM)
    message("NOTICE: random enabled")
    target_compile_definitions(noconnect PUBLIC -DNOCONNECT_RANDOM)
else()
    message("NOTICE: random disabled")
endif()
