cmake_minimum_required(VERSION 3.25)
project(xrpl_rental_hooks C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(xrpl_rental_hooks
        error.h
        extern.h
        hookapi.h
        macro.h
        rental_state_hook.c
        sfcodes.h)
