cmake_minimum_required(VERSION 3.10)
# set the project name
project(rsa_sha_demo)

add_subdirectory(lib)

# add the executable
add_executable(rsa_sha_demo main.c)

target_link_libraries(rsa_sha_demo PUBLIC cyclone_crypto)
if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    target_link_libraries(rsa_sha_demo PUBLIC pthread) # Needed on Linux to compile crypto
endif()