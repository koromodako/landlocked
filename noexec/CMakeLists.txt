cmake_minimum_required(VERSION 3.28)
#
project(NOEXEC VERSION 1.0)
#
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
#
configure_file(noexec.h.in noexec.h)
#
add_library(noexec SHARED landlocked.c noexec.c)
if(DEBUG)
    message("NOTICE: debug enabled")
    target_compile_definitions(noexec PUBLIC -DLANDLOCKED_DEBUG)
else()
    message("NOTICE: debug disabled")
endif()
if(RANDOM)
    message("NOTICE: random enabled")
    target_compile_definitions(noexec PUBLIC -DNOEXEC_RANDOM)
else()
    message("NOTICE: random disabled")
endif()
