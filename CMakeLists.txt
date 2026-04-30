cmake_minimum_required(VERSION 3.14)
project(libcmdx VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------- Options ----------
option(CMDX_BUILD_TESTS "Build tests" ON)
option(BUILD_SHARED_LIBS "Build shared library" OFF)

# ---------- Dependencies ----------
find_package(ZLIB REQUIRED)
find_package(Iconv REQUIRED)

# ICU: try CMake FindICU first, fall back to pkg-config (macOS Homebrew)
find_package(ICU QUIET COMPONENTS uc i18n)
if(ICU_FOUND)
    set(ICU_LIBS ICU::uc ICU::i18n)
elseif(NOT WIN32)
    find_package(PkgConfig REQUIRED)
    if(APPLE)
        set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/opt/homebrew/opt/icu4c/lib/pkgconfig")
    endif()
    pkg_check_modules(ICU_UC REQUIRED IMPORTED_TARGET icu-uc)
    pkg_check_modules(ICU_I18N REQUIRED IMPORTED_TARGET icu-i18n)
    set(ICU_LIBS PkgConfig::ICU_UC PkgConfig::ICU_I18N)
else()
    find_package(ICU REQUIRED COMPONENTS uc i18n)
    set(ICU_LIBS ICU::uc ICU::i18n)
endif()

# ---------- Library ----------
file(GLOB CMDX_SOURCES
    src/*.c
    src/crypto/*.c
    src/minilzo/*.c
    src/utils/*.c
    deps/uobject/src/*.c
)

set(CMDX_PUBLIC_HEADERS
    src/cmdx_reader.h
    src/cmdx_types.h
    src/cmdx_meta.h
)

add_library(cmdx ${CMDX_SOURCES})

target_include_directories(cmdx
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto

        ${CMAKE_CURRENT_SOURCE_DIR}/src/minilzo
        ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/uobject/src
)

target_link_libraries(cmdx
    PUBLIC
        ZLIB::ZLIB
        ${ICU_LIBS}
        Iconv::Iconv
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(cmdx PUBLIC m pthread)
endif()

if(MSVC)
    # C11 atomics still experimental in MSVC; required by deps/uobject
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /experimental:c11atomics")
    target_compile_definitions(cmdx PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(cmdx PRIVATE /W4)
else()
    target_compile_options(cmdx PRIVATE -Wall -Wextra)
endif()

# ---------- Tests ----------
if(CMDX_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------- Install ----------
include(GNUInstallDirs)

install(TARGETS cmdx
    EXPORT cmdxTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES ${CMDX_PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cmdx
)

install(EXPORT cmdxTargets
    FILE cmdxTargets.cmake
    NAMESPACE cmdx::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cmdx
)
