add_library(xrt_coreutil SHARED
   api/xrt_device.cpp
)
target_link_options(xrt_coreutil PRIVATE "-Wl,-Bsymbolic")
install(TARGETS xrt_coreutil)
