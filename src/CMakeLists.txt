set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Select flags.
set(CMAKE_C_FLAGS "-Wall")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -DNDEBUG -g")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -DDEBUG -fno-omit-frame-pointer -fsanitize=address")

set(CMAKE_CXX_FLAGS "-Wall -fno-rtti -fno-exceptions")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wno-unused-value")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O3 -DNDEBUG -g -Wno-unused-value")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fno-omit-frame-pointer -fsanitize=address -DDEBUG")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

# Include 'libdpdk'.
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK_STATIC libdpdk>=23.11 libdpdk<24.0 REQUIRED IMPORTED_TARGET)

# Optional 'libbpf' (>= 1.1 for the user_ring_buffer API): enables the EPS
# channel backend (see src/include/eps_channel.h).
pkg_check_modules(LIBBPF libbpf>=1.1 IMPORTED_TARGET)
if(LIBBPF_FOUND)
  message(STATUS "libbpf found - enabling the Machnet EPS channel backend.")
  add_compile_definitions(MACHNET_EPS_ENABLED)
else()
  message(STATUS "libbpf not found - the Machnet EPS channel backend is disabled.")
endif()

include_directories(ext)
add_subdirectory(ext)

# Check if DPDK is defined, since it's needed for core/. Else build only non-core
# non-DPDK parts.
if(LIBDPDK_STATIC_FOUND)
  include_directories(include)
  add_subdirectory(core)
  add_subdirectory(benchmark)
  enable_testing()
  add_subdirectory(tests)
  add_subdirectory(apps)
  add_subdirectory(tools)
else()
  message(WARNING "DPDK not found and RTE_SDK is not set. Building only msg_gen.")
  add_subdirectory(apps/msg_gen)
endif()
