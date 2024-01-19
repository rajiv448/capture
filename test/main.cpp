#include "core/include/xrt/xrt_device.h"

int main()
{
  xrt::device device{0};
  device.load_xclbin("foo.xclbin");
}
