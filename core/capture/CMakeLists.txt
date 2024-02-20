
add_library(xrt_capture SHARED
capture.cpp)

set(LIBS xrt_coreutil)

if (UNIX)
  list(APPEND LIBS dl bfd)
endif()

add_definitions( -DORG_CALL_BY_FNPTR )

target_link_libraries(xrt_capture PRIVATE ${LIBS})

install(TARGETS xrt_capture)
