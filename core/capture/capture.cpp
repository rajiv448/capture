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
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <elf.h>
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

static std::string find_library_path ()
{
  char *ld_library_path = getenv ("LD_PRELOAD");
  if (ld_library_path == NULL) {
    std::cout << "LD_LIBRARY_PATH is not set." << std::endl;
    return "";
  }

  std::string full_path = std::string (ld_library_path);
  
  return full_path;
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

  /**
   * Get Function address's which are of intrest and ignore others. 
   */
  for (auto it = FunMangled.begin (); it != FunMangled.end (); ++it) {
    auto ptr_itr = MapFuncPtr.find (it->first);

    if (ptr_itr != MapFuncPtr.end ()) {
      void **temp = ptr_itr->second;
      /* update the original function address in the dispatch table */
      *temp = (dlsym (handle, it->second.c_str ()));
      if (NULL == temp) {
        std::cout << "Null Func address received " << std::endl;
      }
    }
  }
  return 1;
}

/**
 * This function will read mangled API's from library  and performs
 * Demangling operation.
 */
int DeviceRouter::load_symbols () {

  path = find_library_path ();

  // Open the ELF file
  std::ifstream elf_file("/home/siva/rk/rjv/capture/build/core/capture/libxrt_capture.so", std::ios::binary);

  if (!elf_file.is_open()) {
      std::cerr << "Failed to open ELF file: " << path << std::endl;
      return 0;
  }

  // Read the ELF header
  Elf64_Ehdr elf_header;
  elf_file.read(reinterpret_cast<char*>(&elf_header), sizeof(Elf64_Ehdr));
  if (!elf_file) {
      std::cerr << "Failed to read ELF header" << std::endl;
      return 0;
  }

  // Check ELF magic number
  if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
      std::cerr << "Not an ELF file" << std::endl;
      return 0;
  }

  // Get the section header table
  elf_file.seekg(elf_header.e_shoff);
  Elf64_Shdr* section_headers = new Elf64_Shdr[elf_header.e_shnum];
  elf_file.read(reinterpret_cast<char*>(section_headers), elf_header.e_shnum * sizeof(Elf64_Shdr));
  if (!elf_file) {
      std::cerr << "Failed to read section header table" << std::endl;
      delete[] section_headers;
      return 0;
  }

  // Find the symbol table section
  Elf64_Shdr* symtab_section = nullptr;
  for (int i = 0; i < elf_header.e_shnum; ++i) {
      if (section_headers[i].sh_type == SHT_DYNSYM) {
          symtab_section = &section_headers[i];
          break;
      }
  }

  if (symtab_section == nullptr) {
      std::cerr << "Symbol table section not found" << std::endl;
      delete[] section_headers;
      return 0;
  }

  // Read and print the mangled function names from the symbol table section
  int num_symbols = symtab_section->sh_size / sizeof(Elf64_Sym);
  for (int i = 0; i < num_symbols; ++i) {
      Elf64_Sym symbol;
      elf_file.seekg(symtab_section->sh_offset + i * sizeof(Elf64_Sym));
      elf_file.read(reinterpret_cast<char*>(&symbol), sizeof(Elf64_Sym));
      if (!elf_file) {
          std::cerr << "Failed to read symbol table entry" << std::endl;
          delete[] section_headers;
          return 0;
      }
      // Check if the symbol is a function
      if ((ELF64_ST_TYPE(symbol.st_info) == STT_FUNC) && 
          (ELF64_ST_BIND(symbol.st_info) == STB_GLOBAL) &&
          (ELF64_ST_VISIBILITY(symbol.st_other) == STV_DEFAULT) &&
          (symbol.st_shndx != SHN_UNDEF))
         {
          char* symbol_name = new char[1000];
          elf_file.seekg(section_headers[symtab_section->sh_link].sh_offset + symbol.st_name);
          elf_file.read(symbol_name, 1000);
          if (!elf_file) {
              std::cerr << "Failed to read symbol name" << std::endl;
              delete[] symbol_name;
              delete[] section_headers;
              return 0;
          }
          //std::cout <<"Mangled name: "<<symbol_name <<std::endl;
          std::string demangled_name = demangle (symbol_name);
          FunMangled[demangled_name] = symbol_name;

          delete[] symbol_name;
      }
  }

  // Clean up
  delete[] section_headers;

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
