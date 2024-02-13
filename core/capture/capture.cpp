#include "core/include/xrt/xrt_device.h"
#include "core/common/api/capture.h"

#include <iostream>
#include <memory>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
#include <functional>

#ifdef _WIN32
bool debug = false;
bool dtable_populated = false;

#ifdef ORG_CALL_BY_FNPTR
typedef xrt::device* (*xrt_device_ctor)(int);
typedef xrt::uuid (xrt::device::*xrt_device_load_xclbin)(const std::string&);
typedef void (xrt::device::*xrt_device_dtor)();

typedef struct _xrt_dtable {
	xrt_device_ctor 		m_xrt_device_ctor;
	xrt_device_load_xclbin	m_xrt_device_load_xclbin;
	xrt_device_dtor			m_xrt_device_dtor;
} xrt_dtable;

xrt_dtable m_xrt_dtable;
#endif

// Make the page writable and replace the function pointer. Once replacement is
// completed restore the page protection.
static void replaceFunction(
    PIMAGE_THUNK_DATA thunk,
    void* pFunction )
{
    // Make page writable temporarily:
    MEMORY_BASIC_INFORMATION mbinfo;
    VirtualQuery( thunk, &mbinfo, sizeof(mbinfo) );
    if( !VirtualProtect(
            mbinfo.BaseAddress,
            mbinfo.RegionSize,
            PAGE_EXECUTE_READWRITE,
            &mbinfo.Protect ) )
    {
        return;
    }

    // Replace function pointer with our implementation:
    thunk->u1.Function = (ULONG64)pFunction;

    // Restore page protection:
    DWORD zero = 0;
    if( !VirtualProtect(
            mbinfo.BaseAddress,
            mbinfo.RegionSize,
            mbinfo.Protect,
            &zero ) )
    {
        return;
    }
}

// Iterate through the IDT for all table entry corresponding to xrt_coreutil.dll
// and replace the function pointer in firstThunk by looking for the same name
// into the xrt_capture.dll for the same name.
int idt_fixup( void *dummy ) {

  if(debug) std::cout << "ENTRY idt_fixup \n";
  LPVOID imageBase = GetModuleHandleA(NULL);
  PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

  PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
  IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
  LPCSTR libraryName = NULL;
  HMODULE library = NULL;
  PIMAGE_IMPORT_BY_NAME functionName = NULL;

  GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                      reinterpret_cast<LPCTSTR>(&idt_fixup), &library);

  while (importDescriptor->Name != NULL)
  {
    libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;

    if ( !stricmp(libraryName, "xrt_coreutil.dll" )) {
      PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
      originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
      firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);
      while (originalFirstThunk->u1.AddressOfData != NULL)
      {
        functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
#ifdef ORG_CALL_BY_FNPTR
		if (!dtable_populated) {
			if ( !strcmp( functionName->Name, "??0device@xrt@@QEAA@I@Z" ) ) {
				std::memcpy(&m_xrt_dtable.m_xrt_device_ctor, &firstThunk->u1.Function, sizeof(firstThunk->u1.Function));
				std::cout << "ctor \t\t= 0x" << std::hex << firstThunk->u1.Function << "\n";
			}

			if ( !strcmp( functionName->Name, "?load_xclbin@device@xrt@@QEAA?AVuuid@2@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z" ) ) {
				std::memcpy(&m_xrt_dtable.m_xrt_device_load_xclbin, &firstThunk->u1.Function, sizeof(firstThunk->u1.Function));
				std::cout << "load_xclbin \t= 0x" << std::hex << firstThunk->u1.Function << "\n";
			}

			if ( !strcmp( functionName->Name, "??1device@xrt@@QEAA@XZ" ) ) {
				std::memcpy(&m_xrt_dtable.m_xrt_device_dtor, &firstThunk->u1.Function, sizeof(firstThunk->u1.Function));
				std::cout << "dtor \t\t= 0x" << std::hex << firstThunk->u1.Function << "\n";
			}
		}
#endif //#ifdef ORG_CALL_BY_FNPTR
        void * pFunction = GetProcAddress(library, functionName->Name);
        if(pFunction) {
          replaceFunction( firstThunk, pFunction);
        }

        ++originalFirstThunk;
        ++firstThunk;
      }
    }

    importDescriptor++;
  }

  if(debug) std::cout << "EXIT idt_fixup\n";
  return 0;
}
#endif

namespace xrt {
device::
device(unsigned int index)
  : m_handle(xrt_core::capture::device::device(index))
  //: m_handle(m_xrt_dtable.m_xrt_device_ctor(index))
{
  std::cout << "capture|xrt::device::device(" << index << ")\n";
}

device::
~device()
{
  std::cout << "capture|xrt::device::~device()\n";
#if defined(ORG_CALL_BY_FNPTR) && defined(_WIN32)
  (this->*m_xrt_dtable.m_xrt_device_dtor)();
#endif
}

uuid
device::
load_xclbin(const std::string& fnm)
{
  std::cout << "capture|xrt::device::load_xclbin(" << fnm << ")\n";
#if !defined(ORG_CALL_BY_FNPTR) || !defined(_WIN32)
  return xrt_core::capture::device::load_xclbin(*this, fnm);
#else
  return (this->*m_xrt_dtable.m_xrt_device_load_xclbin)(fnm);
#endif
}

} // xrt
