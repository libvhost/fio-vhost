cmake_minimum_required(VERSION 3.0)
project(fio-vhost LANGUAGES C CXX VERSION 3.27.417)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

#set(ENABLE_SANITIZERS true CACHE BOOL "Enable Sanitizers")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

# example: https://github.com/amzn/hawktracer/blob/master/CMakeLists.txt
# https://github.com/soedinglab/hh-suite/blob/master/CMakeLists.txt

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
#if (ENABLE_SANITIZERS)
    include(FindUBSan)
    include(FindASan)
    include(FindMSan)
    include(FindTSan)
#endif()

include(ProcessorCount)
include(ExternalProject)
ProcessorCount(N)

set(FIO_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fio)

include_directories(${FIO_SOURCE_DIR})
link_directories(${CMAKE_CURRENT_BINARY_DIR})

# Workaround for the centos 7 compile error, the strsep has duplicate name.
add_compile_definitions(FIO_STRSEP_LIB_H)

include_directories(${CMAKE_SOURCE_DIR})
ExternalProject_Add(fio-ext
    SOURCE_DIR ${FIO_SOURCE_DIR}
    CONFIGURE_COMMAND make clean && ./configure --prefix=${CMAKE_BINARY_DIR}
    BUILD_COMMAND make libfio -j ${N} V=1
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND mv libfio_static.a ${CMAKE_CURRENT_BINARY_DIR}
    )

set(LIBISCSI_SOURCE_DIR ${CMAKE_SOURCE_DIR}/libiscsi)
add_subdirectory(libiscsi EXCLUDE_FROM_ALL)
add_subdirectory(libvhost)
#add_subdirectory(libvfio)
add_subdirectory(plugins)
include_directories(.)

###################################### RPM ##############################
execute_process(COMMAND git rev-parse --short HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE COMMIT_HASH ERROR_VARIABLE error
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if (error)
  message(FATAL_ERROR ${error})
endif()

SET(CPACK_RPM_COMPONENT_INSTALL 1)
SET(CPACK_RPM_fio_PACKAGE_NAME fio)
SET(CPACK_RPM_fio_FILE_NAME fio-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}-${COMMIT_HASH}.rpm)
#set(CPACK_GENERATOR "DEB;TGZ;ZIP;RPM")
set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_PACKAGE_MAINTAINER "Feng Li")

set(CPACK_SOURCE_IGNORE_FILES
        "/rpm/"
        "^${PROJECT_SOURCE_DIR}/build/"
        "^${PROJECT_SOURCE_DIR}/.git/"
        "^${PROJECT_SOURCE_DIR}/.gitignore"
        "^${PROJECT_SOURCE_DIR}/.gitattributes"
        )
include(CPack)
