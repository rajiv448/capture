add_library(xrt_capture SHARED
   capture.cpp)

target_link_libraries(xrt_capture
   PRIVATE
   xrt_coreutil)

install(TARGETS xrt_capture)
