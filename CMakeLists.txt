cmake_minimum_required(VERSION 3.15)
project(FilelessDLLLoader VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files
add_executable(FilelessDLLLoader
    src/main.cpp
    src/NetworkStream.cpp
    src/PEMapper.cpp
    src/ThreadHijacker.cpp
    src/PanicFunction.cpp
)

target_include_directories(FilelessDLLLoader PRIVATE include)

# Windows specific libraries
if(WIN32)
    target_link_libraries(FilelessDLLLoader PRIVATE ws2_32)
endif()

# Example DLL that can be injected
add_library(ExamplePayload SHARED
    examples/ExamplePayload.cpp
)

# Set warning levels
if(MSVC)
    target_compile_options(FilelessDLLLoader PRIVATE /W4)
else()
    target_compile_options(FilelessDLLLoader PRIVATE -Wall -Wextra -Wpedantic)
endif()
