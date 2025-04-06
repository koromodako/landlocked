cmake_minimum_required(VERSION 3.28)
#
project(NOMOD VERSION 1.0)
#
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
#
configure_file(nomod.h.in nomod.h)
#
add_library(nomod SHARED landlocked.c nomod.c)
if(DEBUG)
    message("NOTICE: debug enabled")
    target_compile_definitions(nomod PUBLIC -DLANDLOCKED_DEBUG)
else()
    message("NOTICE: debug disabled")
endif()
