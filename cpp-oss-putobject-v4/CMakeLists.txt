cmake_minimum_required(VERSION 3.14)
project(oss_putobject_v4 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_executable(oss_putobject_v4 src/main.cpp)
target_include_directories(oss_putobject_v4 PRIVATE include)
target_link_libraries(oss_putobject_v4 PRIVATE OpenSSL::Crypto CURL::libcurl)

# 离线自测：用官方文档示例向量验证签名实现（无需网络与真实 AK）
add_executable(v4_selftest test/test_signature.cpp)
target_include_directories(v4_selftest PRIVATE include)
target_link_libraries(v4_selftest PRIVATE OpenSSL::Crypto)

enable_testing()
add_test(NAME v4_selftest COMMAND v4_selftest)
