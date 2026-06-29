cmake_minimum_required(VERSION 3.20)

project(mpcrypt)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


add_library(mpcrypt
    src/Sha256.cpp
    src/Aes.cpp
    src/VideoCrypt.cpp
    3rdparty/tinyaes/aes.c
)

target_include_directories(mpcrypt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
        3rdparty
)

# 安装mpcrypt库
install(TARGETS mpcrypt
    EXPORT mpcryptTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# 安装公共头文件
install(DIRECTORY include/ DESTINATION include/mpcrypt
    FILES_MATCHING PATTERN "*.h"
)

# 生成并安装 CMake 配置文件
install(EXPORT mpcryptTargets
    FILE mpcryptTargets.cmake
    NAMESPACE mpcrypt::
    DESTINATION lib/cmake/mpcrypt
)
