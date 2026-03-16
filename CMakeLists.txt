cmake_minimum_required(VERSION 3.25)
project(KeyGenerator VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(DEFINED ENV{KEY_GENERATOR_INSTALL_PREFIX} AND NOT "$ENV{KEY_GENERATOR_INSTALL_PREFIX}" STREQUAL "")
    set(_key_generator_install_prefix "$ENV{KEY_GENERATOR_INSTALL_PREFIX}")
elseif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT OR
       CMAKE_INSTALL_PREFIX STREQUAL "/usr/local" OR
       CMAKE_INSTALL_PREFIX STREQUAL "/Users/furkanozen/Documents/Libraries" OR
       CMAKE_INSTALL_PREFIX STREQUAL "")
    set(_key_generator_install_prefix "/Users/furkanozen/Documents/Libraries/KeyGenerator")
endif()

if(DEFINED _key_generator_install_prefix)
    set(CMAKE_INSTALL_PREFIX "${_key_generator_install_prefix}" CACHE PATH "Install prefix" FORCE)
    unset(_key_generator_install_prefix)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(KEY_GENERATOR_BUILD_DEMO "Build the demo executable" ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(SessionKeyGenerator
    src/SessionKeyGenerator.cpp
    src/OpenSslHkdfSessionKeyGenerator.cpp
)

add_library(KeyGenerator::SessionKeyGenerator ALIAS SessionKeyGenerator)

target_include_directories(SessionKeyGenerator
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/KeyGenerator>
)

target_link_libraries(SessionKeyGenerator
    PUBLIC
        OpenSSL::Crypto
        Threads::Threads
)

target_compile_features(SessionKeyGenerator PUBLIC cxx_std_20)

set_target_properties(SessionKeyGenerator PROPERTIES
    EXPORT_NAME SessionKeyGenerator
)

if(KEY_GENERATOR_BUILD_DEMO)
    add_executable(key_generator_demo src/main.cpp)
    target_link_libraries(key_generator_demo PRIVATE KeyGenerator::SessionKeyGenerator)
endif()

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/KeyGeneratorConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/KeyGeneratorConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/KeyGeneratorConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/KeyGenerator"
)

install(
    TARGETS SessionKeyGenerator
    EXPORT KeyGeneratorTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/KeyGenerator"
)

install(
    EXPORT KeyGeneratorTargets
    FILE KeyGeneratorTargets.cmake
    NAMESPACE KeyGenerator::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/KeyGenerator"
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/KeyGeneratorConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/KeyGeneratorConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/KeyGenerator"
)
