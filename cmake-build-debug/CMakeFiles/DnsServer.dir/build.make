# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.29

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/yusuf/Desktop/clion/bin/cmake/linux/x64/bin/cmake

# The command to remove a file.
RM = /home/yusuf/Desktop/clion/bin/cmake/linux/x64/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yusuf/CLionProjects/BasicDnsServer

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/DnsServer.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/DnsServer.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/DnsServer.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/DnsServer.dir/flags.make

CMakeFiles/DnsServer.dir/src/main.cpp.o: CMakeFiles/DnsServer.dir/flags.make
CMakeFiles/DnsServer.dir/src/main.cpp.o: /home/yusuf/CLionProjects/BasicDnsServer/src/main.cpp
CMakeFiles/DnsServer.dir/src/main.cpp.o: CMakeFiles/DnsServer.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/DnsServer.dir/src/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/DnsServer.dir/src/main.cpp.o -MF CMakeFiles/DnsServer.dir/src/main.cpp.o.d -o CMakeFiles/DnsServer.dir/src/main.cpp.o -c /home/yusuf/CLionProjects/BasicDnsServer/src/main.cpp

CMakeFiles/DnsServer.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/DnsServer.dir/src/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yusuf/CLionProjects/BasicDnsServer/src/main.cpp > CMakeFiles/DnsServer.dir/src/main.cpp.i

CMakeFiles/DnsServer.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/DnsServer.dir/src/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yusuf/CLionProjects/BasicDnsServer/src/main.cpp -o CMakeFiles/DnsServer.dir/src/main.cpp.s

CMakeFiles/DnsServer.dir/src/header/dns.cpp.o: CMakeFiles/DnsServer.dir/flags.make
CMakeFiles/DnsServer.dir/src/header/dns.cpp.o: /home/yusuf/CLionProjects/BasicDnsServer/src/header/dns.cpp
CMakeFiles/DnsServer.dir/src/header/dns.cpp.o: CMakeFiles/DnsServer.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/DnsServer.dir/src/header/dns.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/DnsServer.dir/src/header/dns.cpp.o -MF CMakeFiles/DnsServer.dir/src/header/dns.cpp.o.d -o CMakeFiles/DnsServer.dir/src/header/dns.cpp.o -c /home/yusuf/CLionProjects/BasicDnsServer/src/header/dns.cpp

CMakeFiles/DnsServer.dir/src/header/dns.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/DnsServer.dir/src/header/dns.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yusuf/CLionProjects/BasicDnsServer/src/header/dns.cpp > CMakeFiles/DnsServer.dir/src/header/dns.cpp.i

CMakeFiles/DnsServer.dir/src/header/dns.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/DnsServer.dir/src/header/dns.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yusuf/CLionProjects/BasicDnsServer/src/header/dns.cpp -o CMakeFiles/DnsServer.dir/src/header/dns.cpp.s

# Object files for target DnsServer
DnsServer_OBJECTS = \
"CMakeFiles/DnsServer.dir/src/main.cpp.o" \
"CMakeFiles/DnsServer.dir/src/header/dns.cpp.o"

# External object files for target DnsServer
DnsServer_EXTERNAL_OBJECTS =

DnsServer: CMakeFiles/DnsServer.dir/src/main.cpp.o
DnsServer: CMakeFiles/DnsServer.dir/src/header/dns.cpp.o
DnsServer: CMakeFiles/DnsServer.dir/build.make
DnsServer: /usr/lib/libboost_system.so.1.86.0
DnsServer: /usr/lib/libssl.so
DnsServer: /usr/lib/libcrypto.so
DnsServer: CMakeFiles/DnsServer.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable DnsServer"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/DnsServer.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/DnsServer.dir/build: DnsServer
.PHONY : CMakeFiles/DnsServer.dir/build

CMakeFiles/DnsServer.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/DnsServer.dir/cmake_clean.cmake
.PHONY : CMakeFiles/DnsServer.dir/clean

CMakeFiles/DnsServer.dir/depend:
	cd /home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yusuf/CLionProjects/BasicDnsServer /home/yusuf/CLionProjects/BasicDnsServer /home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug /home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug /home/yusuf/CLionProjects/BasicDnsServer/cmake-build-debug/CMakeFiles/DnsServer.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/DnsServer.dir/depend

