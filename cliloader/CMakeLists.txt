set(SOURCE_FILES
  cliloader.cpp
)

if (WIN32)
list(APPEND SOURCE_FILES
  getopt.c
)
endif()

add_executable(cliloader ${SOURCE_FILES})
install(TARGETS cliloader)
