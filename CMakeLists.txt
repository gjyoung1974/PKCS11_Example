cmake_minimum_required(VERSION 3.15)
project(pkcs11_demo_new)

pwd
include_directories(/usr/include/c++/9/x86_64-redhat-linux)
add_executable(pkcs11_demo_new main.cpp testing.cpp testing.h)
target_link_libraries(pkcs11_demo_new ${CMAKE_DL_LIBS})