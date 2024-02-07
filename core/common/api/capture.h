#ifndef capture_h
#define capture_h

#include "core/include/xrt/xrt_device.h"
#include <string>

// This are internal APIs called by the capture library
// The APIs are implemented in xrt_coreutil
namespace xrt_core::capture {

// Define in xrt_device.cpp
namespace device {

std::shared_ptr<xrt::device_impl>
device(unsigned int index);

xrt::uuid
load_xclbin(xrt::device& device, const std::string&);

}

// Define in xrt_bo.cpp
namespace bo {
}

// Define in xrt_kernel.cpp
namespace kernel {
}

// Define in xrt_kernel.cpp
namespace run {
}
  
} // xrt_core::capture

#ifdef _WIN32
#ifdef __cplusplus
extern "C" {
#endif
	int idt_fixup( void *dummy );
#ifdef __cplusplus
}
#endif
#endif

#endif
