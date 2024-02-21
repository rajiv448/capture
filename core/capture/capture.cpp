#include "core/include/xrt/xrt_device.h"
#include "core/common/api/capture.h"

#include <iostream>
#include <memory>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
#include <functional>

#ifdef ORG_CALL_BY_FNPTR
typedef xrt::device * (*xrt_device_ctor) (void *, int);
typedef xrt::uuid (xrt::device::*xrt_device_load_xclbin) (const std::string &);
typedef void (xrt::device::*xrt_device_dtor) ();

typedef struct _xrt_dtable {
  xrt_device_ctor m_xrt_device_ctor;
  xrt_device_load_xclbin m_xrt_device_load_xclbin;
  xrt_device_dtor m_xrt_device_dtor;
} xrt_dtable;

xrt_dtable m_xrt_dtable;

#endif

#ifdef __linux__
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <bfd.h>
#include <cxxabi.h>
#include <dlfcn.h>

#define LIB_NAME  ("libxrt_coreutil.so")

/* This will create association between function name 
 * and  function pointer of the original library file 
 * which will be used to invoke API's from original library. 
 */
std::unordered_map < std::string, void **> MapFuncPtr = {
  {"xrt::device::device(unsigned int)", (void **) &m_xrt_dtable.m_xrt_device_ctor},
  {"xrt::device::load_xclbin(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)",
      (void **) &m_xrt_dtable.m_xrt_device_load_xclbin},
  {"xrt::device::~device()", (void **) &m_xrt_dtable.m_xrt_device_dtor}
};

/* 
 * This will create association between function name (key)
 * and mangled function name (value).
 */
std::unordered_map < std::string, std::string > FunMangled;

/**
 * This class will perform following operations. 
 * 1. Read mangled symbols from .so file. 
 * 2. perform demangling operation. 
 * 3. update xrt_dtable which will be used to invoke original API's
 */
class DeviceRouter
{
private:
  void *handle;
  /*library Path */
  std::string path;

public:
  int load_func_addr ();
  int load_symbols ();

  static std::shared_ptr < DeviceRouter > getDeviceRouterInstance ()  {
    static auto ptr = std::make_shared < DeviceRouter > ();
    return ptr;
  }

  DeviceRouter ()
  {
    if (!load_symbols ()) {
      std::cout << "Failed to load symbols exiting application " << std::endl;
      exit (1);
    } else if (!load_func_addr ()) {
      std::cout << "Failed to load function address exiting application " << std::endl;
      exit (1);
    }
  }

  ~DeviceRouter () {
    if (handle)
      dlclose (handle);
  }
};

/**
 * This function demangles the input mangled function.
 */
static std::string demangle (const char *mangled_name)
{
  int status;
  char *demangled_name = abi::__cxa_demangle (mangled_name, nullptr, nullptr, &status);
  if (status == 0) {
    std::string result (demangled_name);
    free (demangled_name);
    return result;
  } else {
    // Demangling failed
    return std::string (mangled_name);
  }
}

static std::string find_library_path (const char *library_name)
{
  char *ld_library_path = getenv ("LD_LIBRARY_PATH");
  if (ld_library_path == NULL) {
    std::cout << "LD_LIBRARY_PATH is not set." << std::endl;
    return "";
  }

  char *ld_library_path_copy = strdup (ld_library_path);
  if (ld_library_path_copy == nullptr) {
    std::cerr << "Error: Failed to allocate memory." << std::endl;
    return "";
  }

  char *path = strtok (ld_library_path_copy, ":");
  while (path != NULL) {
    std::string full_path = std::string (path) + "/" + library_name;
    if (access (full_path.c_str (), F_OK) != -1) {
      free (ld_library_path_copy);
      return full_path;
    }
    path = strtok (NULL, ":");
  }

  free (ld_library_path_copy);
  return "";
}

/**
 * This function will update the dispatch table 
 * with address of the functions from original 
 * library. 
 */
int DeviceRouter::load_func_addr ()
{
  // Load the shared object file
  handle = dlopen (LIB_NAME, RTLD_LAZY);
  if (!handle) {
    std::cerr << "Error loading shared library: " << dlerror () << std::endl;
    return 0;
  }

  for (auto it = FunMangled.begin (); it != FunMangled.end (); ++it) {
    auto ptr_itr = MapFuncPtr.find (it->first);

    if (ptr_itr != MapFuncPtr.end ()) {
      void **temp = ptr_itr->second;
      /* update the original function address in the dispatch table */
      *temp = (dlsym (handle, it->second.c_str ()));
      if (NULL == temp) {
        std::cout << "Null Func address received " << std::endl;
      }
    } else {
      std::cout << "Func not found: " << it->first << std::endl;
    }
  }
  return 1;
}

/**
 * This function will read mangled API's from library  and performs
 * Demangling operation.
 */
int DeviceRouter::load_symbols ()
{
  path = find_library_path (LIB_NAME);

  if (path.empty ()) {
    std::cout << "unable to find library: " << LIB_NAME << std::endl;
    return 0;
  }

  bfd *file = bfd_openr (path.c_str (), nullptr);
  if (!file) {
    std::cerr << "Error: Failed to open file." << std::endl;
    return 0;
  }

  bfd_init ();

  if (!bfd_check_format (file, bfd_object)) {
    std::cerr << "Error: Not an object file." << std::endl;
    bfd_close (file);
    return 0;
  }

  long storage_needed = bfd_get_symtab_upper_bound (file);
  if (storage_needed < 0) {
    std::cerr << "Error: Failed to get symbol table upper bound." << std::endl;
    bfd_close (file);
    return 0;
  }

  asymbol **symbol_table = (asymbol **) malloc (storage_needed);
  if (!symbol_table) {
    std::cerr << "Error: Failed to allocate memory for symbol table." << std::
        endl;
    bfd_close (file);
    return 0;
  }

  long symbols = bfd_canonicalize_symtab (file, symbol_table);
  if (symbols < 0) {
    std::cerr << "Error: Failed to read symbol table." << std::endl;
    free (symbol_table);
    bfd_close (file);
    return 0;
  }

  for (long i = 0; i < symbols; ++i) {
    // Skip if the Symbol is not global
    if (!(symbol_table[i]->flags & BSF_GLOBAL)) {
      continue;
    }
    // Check if the symbol is mangled
    if (symbol_table[i]->name && symbol_table[i]->name[0] == '_') {
      const char *pcstr = symbol_table[i]->name;
      std::string symbol = pcstr;
      std::string demangled_name = demangle (symbol_table[i]->name);
      FunMangled[demangled_name] = symbol_table[i]->name;
    }
  }

  free (symbol_table);
  bfd_close (file);
  return 1;
}

std::shared_ptr <DeviceRouter> dptr =  DeviceRouter::getDeviceRouterInstance ();

#elif _WIN32

bool debug = false;
bool dtable_populated = false;

#ifdef ORG_CALL_BY_FNPTR
char func_name[3][256] = {
    "xrt::device::device(unsigned int)",
    "class xrt::uuid xrt::device::load_xclbin(class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > const &)",
    "xrt::device::~device(void)"
  };

#endif

#include <Dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")
std::string demangle(const char* mangled) {
  /* TODO : for some reason UnDecorateSymbolName is not returning size
  hence we are using static rather than dynamic allocation.
  DWORD length = UnDecorateSymbolName(mangled, nullptr, 0, UNDNAME_NAME_ONLY);
    if (length == 0) {
        // Din't returned the allocator size
        std::cout << " length returned is 0?\n";
        return mangled;
    }
  */

  DWORD length = 256;
    std::unique_ptr<char[]> buffer(new char[length]);
    UnDecorateSymbolName(mangled, buffer.get(), length,
      UNDNAME_NO_ACCESS_SPECIFIERS | UNDNAME_NO_ALLOCATION_LANGUAGE |
      UNDNAME_NO_ALLOCATION_MODEL | UNDNAME_NO_MS_KEYWORDS);
    //UNDNAME_NAME_ONLY);

    return std::string(buffer.get());
}


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
        int i;
        for (i=0; i<3; i++) {
          if(!strcmp( demangle(functionName->Name).c_str(), func_name[i] ))
            break;
        }

        if (i < 3) {
          char* dest = reinterpret_cast<char*>(&m_xrt_dtable) + (i * sizeof(xrt_device_ctor));
          std::memcpy(dest, &firstThunk->u1.Function, sizeof(firstThunk->u1.Function));
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

namespace xrt
{
  device::device (unsigned int index)
#if !defined(ORG_CALL_BY_FNPTR)
  :m_handle (xrt_core::capture::device::device (index))
#endif
  {
#if defined(ORG_CALL_BY_FNPTR)
    (m_xrt_dtable.m_xrt_device_ctor) (this, index);
    m_handle = this->get_handle ();
#endif
    std::cout << "capture|xrt::device::device(" << index << ")\n";
  }

  device::~device ()
  {
    std::cout << "capture|xrt::device::~device()\n";
#if defined(ORG_CALL_BY_FNPTR)
    (this->*m_xrt_dtable.m_xrt_device_dtor) ();
#endif
  }

  uuid device::load_xclbin (const std::string & fnm)
  {
    std::cout << "capture|xrt::device::load_xclbin(" << fnm << ")\n";
#if defined(ORG_CALL_BY_FNPTR)
    return (this->*m_xrt_dtable.m_xrt_device_load_xclbin) (fnm);
#else
    return xrt_core::capture::device::load_xclbin (*this, fnm);
#endif
  }

}                               // xrt
