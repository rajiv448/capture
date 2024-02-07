# Demo capture API use for later replay
Demo API capture for replay

# Summary
The project builds two libraries
- libxrt_coreutil.so
- libxrt_capture.so

Application code (sample in `capture/test/main.cpp`) links with `libxrt_coreutil` as normal.
To capture API calls use `LD_PRELOAD` with `libxrt_capture`

# Code organization
Mirrors code from https://github.com/Xilinx/XRT.

```
capture
├── cliloader
│   ├── cliloader.cpp
│   └── CMakeLists.txt
├── CMakeLists.txt
├── core
│   ├── capture
│   │   ├── capture.cpp
│   │   └── CMakeLists.txt
│   ├── common
│   │   ├── api
│   │   │   ├── capture.h
│   │   │   └── xrt_device.cpp
│   │   └── CMakeLists.txt
│   └── include
│       └── xrt
│           ├── CMakeLists.txt
│           └── xrt_device.h
├── LICENSE
├── README.md
└── test
    ├── CMakeLists.txt
        └── main.cpp
```

The capture library is built from `core/capture` into `libxrt_capture`
and linked with `libxrt_coreutil`.

The capture implementation redefines the XRT API symbols defined in
`libxrt_coreutil` which needs to be captured into a time line, for
example `xrt::device` APIs are defined in `libxrt_capture`.

The idea is that if `libxrt_capture` is loaded before `libxrt_coreutil`
then the defintion of exported APIs will come from `libxrt_capture`.
The implementation of the APIs in `libxrt_capture` will do what it
needs to do in terms of capturing the API calls and then call into
`libxrt_coreutil` for the actual implementation of the APIs.

To avoid recursive calls into `libxrt_capture`, the calls from this
library into `libxrt_coreutil` must be into wrapper functions that
immediately calls the public API implementation.  These wrappers are
implemented in the same compilation units that define the actual
public APIs (e.g. `xrt_device.cpp`).

Since all public XRT objects are implemented in an opaque pimpl, the
wrappers can create a *real* XRT object and just steal the opaque
impl. So any XRT object created from `libxrt_capture` will be a valid
object that can be used with our without going through the capture library.

The library `libxrt_coreutil` is built with `-Bdynamic` link option which
ensure that symbols referenced in `libxrt_coreutil` are resolved within
this library and wont recurse to `libxrt_capture`.

To support interception on windows we have added `cliloader`. This application
would load the application and do platform dependent plumbing. For now, this 
application only supporting windows, we would add linux support soon.

On windows platform `cliloader` launches the application in a child process in
suspended state the loads the `xrt_capture.dll`. It then updates the function
pointer in the IDT to point to the `xrt_capture.dll` instead of
`xrt_coreutil.dll`. Once IDT is updated, it lets the child process run and
waits for completion. 

## Building
Build using CMake from root directory.
```
% mkdir build
% cd build
% cmake ..
% cmake --build . --config Debug --verbose --target install
````
This builds `libxrt_coreutil`, `libxrt_capture`, and `main` test executuble.

## Run (Linux)
Run the test making sure `LD_LIBRARY_PATH` can find `libxrt_coreutil` then run as

```
% ldd main
	linux-vdso.so.1 (0x00007fff353e9000)
	libxrt_coreutil.so => /mnt/c/Users/stsoe/git/stsoe/capture/build/lib/libxrt_coreutil.so (0x00007fe8411c4000)
	libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007fe840fd0000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fe840fb5000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe840dc3000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fe840c74000)
% main
xrt::device_impl::device_impl(0)
xrt::device::device(0)
xrt::device::load_xclbin(foo.xclbin)
xrt::device::~device()
xrt::device_impl::~device_impl()
```

## Capture (Linux)
Use LD_PRELOAD to preload `libxrt_capture`.

```
% env LD_PRELOAD=$PWD/lib/libxrt_capture.so bin/main
xrt::device_impl::device_impl(0)
xrt::device::device(0)
xrt::device::~device()
capture|xrt::device::device(0)
capture|xrt::device::load_xclbin(foo.xclbin)
xrt::device::load_xclbin(foo.xclbin)
capture|xrt::device::~device()
xrt::device_impl::~device_impl()

% env LD_PRELOAD=$PWD/lib/libxrt_capture.so bin/main |grep capture
capture|xrt::device::device(0)
capture|xrt::device::load_xclbin(foo.xclbin)
capture|xrt::device::~device()
```

## Run (Windows)
Run the main.exe to execute the application as follows from the build directory
following also show the library dependancies.

```
>dumpbin /DEPENDENTS bin\main.exe
Microsoft (R) COFF/PE Dumper Version 14.38.33133.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file bin\main.exe

File Type: EXECUTABLE IMAGE

  Image has the following dependencies:

    xrt_coreutil.dll
    MSVCP140D.dll
    VCRUNTIME140D.dll
    VCRUNTIME140_1D.dll
    ucrtbased.dll
    KERNEL32.dll
...

>bin\main.exe
xrt::device_impl::device_impl(0)
xrt::device::device(0)
xrt::device::load_xclbin(foo.xclbin)
xrt::device::~device()
xrt::device_impl::~device_impl()

```

## Capture (Windows)
From build directory launch main.exe application using cliloader.exe as follows

```
>bin\cliloader.exe bin\main.exe
xrt::device_impl::device_impl(0)
xrt::device::device(0)
xrt::device::~device()
capture|xrt::device::device(0)
capture|xrt::device::load_xclbin(foo.xclbin)
xrt::device::load_xclbin(foo.xclbin)
capture|xrt::device::~device()
xrt::device_impl::~device_impl()

>bin\cliloader.exe bin\main.exe | findstr capture
capture|xrt::device::device(0)
capture|xrt::device::load_xclbin(foo.xclbin)
capture|xrt::device::~device()
```

