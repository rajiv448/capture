add_library(xrt_capture SHARED
   capture.cpp)

add_definitions( -DORG_CALL_BY_FNPTR )

target_link_libraries(xrt_capture
   PRIVATE
   xrt_coreutil)

install(TARGETS xrt_capture)
