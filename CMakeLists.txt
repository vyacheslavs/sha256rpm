cmake_minimum_required(VERSION 3.14)

project(sha256rpm LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(sha256rpm
  main.cpp
)

target_link_libraries(sha256rpm rpm rpmio OpenSSL::SSL)
