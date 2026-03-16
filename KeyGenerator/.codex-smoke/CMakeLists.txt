cmake_minimum_required(VERSION 3.25)
project(KeyGeneratorSmoke LANGUAGES CXX)

find_package(KeyGenerator CONFIG REQUIRED)

add_executable(key_generator_smoke main.cpp)
target_link_libraries(key_generator_smoke PRIVATE KeyGenerator::SessionKeyGenerator)
