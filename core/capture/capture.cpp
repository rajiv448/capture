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
