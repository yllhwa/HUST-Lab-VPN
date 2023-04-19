cmake_minimum_required(VERSION 3.16)
project(HustVPN)

set(CMAKE_CXX_STANDARD 14)

add_executable(HustVPN main.cpp VPNServer.cpp VPNServer.h VPNClient.cpp VPNClient.h utils.cpp utils.h)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(HustVPN ssl crypto crypt Threads::Threads)