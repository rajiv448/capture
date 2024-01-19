cmake_minimum_required(VERSION 3.16.0)
project(CAPTURE)

if (NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
endif (NOT CMAKE_CXX_STANDARD)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}" CACHE PATH "..." FORCE)

include_directories(
  ${CAPTURE_SOURCE_DIR}
)

set (XRT_INSTALL_DIR           "xrt")
set (XRT_INSTALL_BIN_DIR       "${XRT_INSTALL_DIR}/bin")
set (XRT_INSTALL_INCLUDE_DIR   "${XRT_INSTALL_DIR}/include")
set (XRT_INSTALL_LIB_DIR       "${XRT_INSTALL_DIR}/lib${LIB_SUFFIX}")
set (XRT_NAMELINK_ONLY NAMELINK_ONLY)
set (XRT_NAMELINK_SKIP NAMELINK_SKIP)

add_subdirectory(core/capture)
add_subdirectory(core/common)
add_subdirectory(core/include/xrt)
add_subdirectory(test)

