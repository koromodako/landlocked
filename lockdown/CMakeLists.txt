cmake_minimum_required(VERSION 3.28)
#
project(LOCKDOWN VERSION 1.0)
#
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
#
configure_file(lockdown.h.in lockdown.h)
#
add_library(lockdown SHARED landlocked.c lockdown.c)
if(DEBUG)
    message("NOTICE: debug enabled")
    target_compile_definitions(lockdown PUBLIC -DLANDLOCKED_DEBUG)
else()
    message("NOTICE: debug disabled")
endif()
