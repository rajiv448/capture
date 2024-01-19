add_executable(main main.cpp)
target_link_libraries(main xrt_coreutil)
install(TARGETS main)
