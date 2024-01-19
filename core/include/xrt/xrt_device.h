#ifndef xrt_device_h
#define xrt_device_h
#include <memory>
#include <string>

namespace xrt {

class uuid {};

class device_impl;  // aka xrt_core::device
class device
{
  std::shared_ptr<device_impl> m_handle;
public:
  device(unsigned int index);
  ~device();

  uuid
  load_xclbin(const std::string& xfname);

public:
  std::shared_ptr<xrt::device_impl>
  get_handle() const
  {
    return m_handle;
  }
};

} // xrt

#endif
