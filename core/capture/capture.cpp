#include "core/include/xrt/xrt_device.h"
#include "core/common/api/capture.h"

#include <iostream>
#include <memory>
#include <string>

namespace xrt {

device::
device(unsigned int index)
  : m_handle(xrt_core::capture::device::device(index))
{
  std::cout << "capture|xrt::device::device(" << index << ")\n";
}
  
device::
~device()
{
  std::cout << "capture|xrt::device::~device()\n";
}

uuid
device::
load_xclbin(const std::string& fnm)
{
  std::cout << "capture|xrt::device::load_xclbin(" << fnm << ")\n";
  return xrt_core::capture::device::load_xclbin(*this, fnm);
}

} // xrt
