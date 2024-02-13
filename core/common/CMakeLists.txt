add_library(xrt_coreutil SHARED
   api/xrt_device.cpp
)

add_definitions( -DORG_CALL_BY_FNPTR )

if(UNIX)
  target_link_options(xrt_coreutil PRIVATE "-Wl,-Bsymbolic")
endif()

install(TARGETS xrt_coreutil)
