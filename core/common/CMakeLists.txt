add_library(xrt_coreutil SHARED
   api/xrt_device.cpp
)

if(UNIX)
target_link_options(xrt_coreutil PRIVATE "-Wl,-Bsymbolic")
endif()
install(TARGETS xrt_coreutil)
