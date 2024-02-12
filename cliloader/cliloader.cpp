#include <iostream>
#include <windows.h>
#include "getopt.h"

#define MAX_NUM_DLL 5
#define DEBUG(_s, ...) \
  if(debug) fprintf(stderr, "[cliloader debug] " _s, ##__VA_ARGS__ );

bool debug = false;

static void die(const char *op) {
  fprintf(stderr, "cliloader Error: %s\n", op );
  exit(1);
}

static bool checkWow64(HANDLE parent, HANDLE child) {
  BOOL parentWow64 = FALSE;
  IsWow64Process(parent, &parentWow64);

  BOOL childWow64 = FALSE;
  IsWow64Process(child, &childWow64);

  if( parentWow64 != childWow64 ) {
    fprintf(stderr, "This is the %d-bit version of cliloader, but the target "
      "application is a %d-bit application.\n", parentWow64 ? 32 : 64,
      childWow64 ? 32 : 64 );
    fprintf(stderr, "Execution will continue, but intercepting and profiling "
      "will be disabled.\n");
    return false;
  }

  return true;
}

int main(int argc, char *argv[]) {
  int option;
  int dll_idx = 0;
  std::string dllpath[MAX_NUM_DLL];
  HMODULE h_dll[MAX_NUM_DLL];
  LPTHREAD_START_ROUTINE idt_fixup[MAX_NUM_DLL] = {NULL};

  while ((option = getopt(argc, argv, "vl:")) != -1 ) {
    switch (option) {
      case 'v':
        debug = true;
        break;

      case 'l':
        if ( dll_idx >= MAX_NUM_DLL ) {
          std::cout << "Max number of dll exceeded supported limit(" \
            << MAX_NUM_DLL << "). Exiting .. \n";
          exit(1);
        }
        dllpath[dll_idx++] = optarg;
        break;
    }
  }

  std::string apppath = argv[optind];
  if(debug)
    std::cout << "Application to intercept = " << apppath << std::endl;

  for (int idx = 0; idx < dll_idx; idx++) {
    if(debug) std::cout << "dllpath = " << dllpath[idx] << std::endl;
  }

  for (int idx = 0; idx < dll_idx; idx++) {
    h_dll[idx] = LoadLibraryA(dllpath[idx].c_str());

    if( h_dll[idx] == NULL ) {
      std::cout << "Loading " << dllpath[idx] << " failed\n Exiting ...\n";
      exit(1);
    }

    if (debug) std::cout << dllpath[idx] << " loaded\n";

    idt_fixup[idx] = (LPTHREAD_START_ROUTINE)GetProcAddress(h_dll[idx],
                          "idt_fixup" );

    if( idt_fixup[idx] == NULL ) {
      std::cout << "intrumentation hook not found in " << dllpath[idx] \
        << " Exiting ...\n";
      exit(1);
    }

    if(debug)
      std::cout << "intrumentation hook found in " << dllpath[idx] << std::endl;
  }

    // Create child process in suspended state:
    DEBUG("creating child process with command line: %s\n", apppath.c_str());
    PROCESS_INFORMATION pinfo = { 0 };
    STARTUPINFOA sinfo = { 0 };
    sinfo.cb = sizeof(sinfo);
    if( CreateProcessA(
            NULL,                   // lpApplicationName
            (LPSTR)apppath.c_str(), // lpCommandLine
            NULL,                   // lpProcessAttributes
            NULL,                   // lpThreadAttributes
            FALSE,                  // bInheritHandles
            CREATE_SUSPENDED,       // dwCreationFlags
            NULL,                   // lpEnvironment - use the cliloader environment
            NULL,                   // lpCurrentDirectory - use the cliloader drive and directory
            &sinfo,                 // lpStartupInfo
            &pinfo) == FALSE )      // lpProcessInformation (out)
    {
      die("creating child process");
    }
    DEBUG("created child process\n");

    // Check that we don't have a 32-bit and 64-bit mismatch:
    if( checkWow64(GetCurrentProcess(), pinfo.hProcess) ) {
      // There is no 32-bit and 64-bit mismatch.
      // Start intercepting.

    for (int idx = 0; idx < dll_idx; idx++) {
      void *childPath = NULL;
      HANDLE childThread = NULL;

      // Allocate child memory for the full DLL path:
      childPath = VirtualAllocEx(
        pinfo.hProcess,
        NULL,
        dllpath[idx].size() + 1,
        MEM_COMMIT,
        PAGE_READWRITE );

      if( childPath == NULL ) {
        std::cout << "Failed allocating child memory to store " \
          << dllpath[idx] << ". Exitting ...\n";
        exit(1);
      }

      if(debug)
        std::cout << "Allocated child memory to store path of " \
          << dllpath[idx] << "\n";

      // Write DLL path to child:
      if( WriteProcessMemory(
          pinfo.hProcess,
          childPath,
          (void*)dllpath[idx].c_str(),
          dllpath[idx].size() + 1,
          NULL ) == FALSE ) {
        std::cout << "Failed to write the path of " << dllpath[idx] << \
          " in child memory. Exitting ...\n";
        exit(1);
      }

      if(debug)
        std::cout << "Successfully wrote the path of " << dllpath[idx] << "\n";

      // Create a thread to load the intercept DLL in the child process:
      childThread = CreateRemoteThread(
        pinfo.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(
          GetModuleHandleA("kernel32.dll"),
          "LoadLibraryA"),
        childPath,
        0,
        NULL );
      if( childThread == NULL ) {
        die("loading DLL in child process");
      }
      DEBUG("created child thread to load DLL\n");

      // Wait for child thread to complete:
      if( WaitForSingleObject(childThread, INFINITE) != WAIT_OBJECT_0 ) {
        die("waiting for DLL loading");
      }

      DEBUG("child thread to load DLL completed\n");

      CloseHandle(childThread);
      VirtualFreeEx(pinfo.hProcess, childPath, dllpath[0].size() + 1,
        MEM_RELEASE);
      DEBUG("cleaned up child thread to load DLL\n");

      // Create a thread to read the IDT
      childThread = CreateRemoteThread(
        pinfo.hProcess,
        NULL,
        0,
        idt_fixup[idx],
        NULL,
        0,
        NULL );
      if( childThread == NULL ) {
        die("starting idt_fixup in child process");
      }
      DEBUG("created child thread to run idt_fixup\n");

      // Wait for child thread to complete:
      if( WaitForSingleObject(childThread, INFINITE) != WAIT_OBJECT_0 ) {
        die("waiting for idt_fixup run to complete");
      }
      DEBUG("child thread to run idt_fixup completed\n");
      CloseHandle(childThread);
    }
  }

  // Free dll handle
  for (int idx = 0; idx < dll_idx; idx++) {
    FreeModule(h_dll[idx]);
    if (debug) std::cout << "Closed " << h_dll[idx] << " handle\n";
  }

  // Resume child process:
  DEBUG("resuming child process\n");
  if( ResumeThread(pinfo.hThread) == -1 ) {
    die("resuming thread");
  }
  DEBUG("child process resumed\n");

  // Wait for child process to finish
  if( WaitForSingleObject(pinfo.hProcess, INFINITE) != WAIT_OBJECT_0 ) {
    die("waiting for child process failed");
  }
  DEBUG("child process completed, getting exit code\n");

  // Get return code and forward it
  DWORD retval = 0;
  if( GetExitCodeProcess(pinfo.hProcess, &retval) == FALSE ) {
    die("getting child process exit code");
  }
  DEBUG("child process completed with exit code %u (%08X)\n", retval, retval);

  return retval;
}
