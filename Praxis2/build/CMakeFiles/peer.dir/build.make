# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build"

# Include any dependencies generated for this target.
include CMakeFiles/peer.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/peer.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/peer.dir/flags.make

CMakeFiles/peer.dir/src/peer.o: CMakeFiles/peer.dir/flags.make
CMakeFiles/peer.dir/src/peer.o: ../src/peer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/peer.dir/src/peer.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/peer.dir/src/peer.o   -c "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/peer.c"

CMakeFiles/peer.dir/src/peer.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/peer.dir/src/peer.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/peer.c" > CMakeFiles/peer.dir/src/peer.i

CMakeFiles/peer.dir/src/peer.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/peer.dir/src/peer.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/peer.c" -o CMakeFiles/peer.dir/src/peer.s

CMakeFiles/peer.dir/src/server.o: CMakeFiles/peer.dir/flags.make
CMakeFiles/peer.dir/src/server.o: ../src/server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/peer.dir/src/server.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/peer.dir/src/server.o   -c "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/server.c"

CMakeFiles/peer.dir/src/server.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/peer.dir/src/server.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/server.c" > CMakeFiles/peer.dir/src/server.i

CMakeFiles/peer.dir/src/server.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/peer.dir/src/server.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/server.c" -o CMakeFiles/peer.dir/src/server.s

CMakeFiles/peer.dir/src/packet.o: CMakeFiles/peer.dir/flags.make
CMakeFiles/peer.dir/src/packet.o: ../src/packet.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/peer.dir/src/packet.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/peer.dir/src/packet.o   -c "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/packet.c"

CMakeFiles/peer.dir/src/packet.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/peer.dir/src/packet.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/packet.c" > CMakeFiles/peer.dir/src/packet.i

CMakeFiles/peer.dir/src/packet.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/peer.dir/src/packet.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/packet.c" -o CMakeFiles/peer.dir/src/packet.s

CMakeFiles/peer.dir/src/util.o: CMakeFiles/peer.dir/flags.make
CMakeFiles/peer.dir/src/util.o: ../src/util.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/peer.dir/src/util.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/peer.dir/src/util.o   -c "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/util.c"

CMakeFiles/peer.dir/src/util.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/peer.dir/src/util.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/util.c" > CMakeFiles/peer.dir/src/util.i

CMakeFiles/peer.dir/src/util.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/peer.dir/src/util.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/util.c" -o CMakeFiles/peer.dir/src/util.s

CMakeFiles/peer.dir/src/hash_table.o: CMakeFiles/peer.dir/flags.make
CMakeFiles/peer.dir/src/hash_table.o: ../src/hash_table.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/peer.dir/src/hash_table.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/peer.dir/src/hash_table.o   -c "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/hash_table.c"

CMakeFiles/peer.dir/src/hash_table.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/peer.dir/src/hash_table.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/hash_table.c" > CMakeFiles/peer.dir/src/hash_table.i

CMakeFiles/peer.dir/src/hash_table.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/peer.dir/src/hash_table.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/hash_table.c" -o CMakeFiles/peer.dir/src/hash_table.s

CMakeFiles/peer.dir/src/neighbour.o: CMakeFiles/peer.dir/flags.make
CMakeFiles/peer.dir/src/neighbour.o: ../src/neighbour.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/peer.dir/src/neighbour.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/peer.dir/src/neighbour.o   -c "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/neighbour.c"

CMakeFiles/peer.dir/src/neighbour.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/peer.dir/src/neighbour.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/neighbour.c" > CMakeFiles/peer.dir/src/neighbour.i

CMakeFiles/peer.dir/src/neighbour.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/peer.dir/src/neighbour.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/neighbour.c" -o CMakeFiles/peer.dir/src/neighbour.s

CMakeFiles/peer.dir/src/requests.o: CMakeFiles/peer.dir/flags.make
CMakeFiles/peer.dir/src/requests.o: ../src/requests.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/peer.dir/src/requests.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/peer.dir/src/requests.o   -c "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/requests.c"

CMakeFiles/peer.dir/src/requests.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/peer.dir/src/requests.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/requests.c" > CMakeFiles/peer.dir/src/requests.i

CMakeFiles/peer.dir/src/requests.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/peer.dir/src/requests.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/src/requests.c" -o CMakeFiles/peer.dir/src/requests.s

# Object files for target peer
peer_OBJECTS = \
"CMakeFiles/peer.dir/src/peer.o" \
"CMakeFiles/peer.dir/src/server.o" \
"CMakeFiles/peer.dir/src/packet.o" \
"CMakeFiles/peer.dir/src/util.o" \
"CMakeFiles/peer.dir/src/hash_table.o" \
"CMakeFiles/peer.dir/src/neighbour.o" \
"CMakeFiles/peer.dir/src/requests.o"

# External object files for target peer
peer_EXTERNAL_OBJECTS =

peer: CMakeFiles/peer.dir/src/peer.o
peer: CMakeFiles/peer.dir/src/server.o
peer: CMakeFiles/peer.dir/src/packet.o
peer: CMakeFiles/peer.dir/src/util.o
peer: CMakeFiles/peer.dir/src/hash_table.o
peer: CMakeFiles/peer.dir/src/neighbour.o
peer: CMakeFiles/peer.dir/src/requests.o
peer: CMakeFiles/peer.dir/build.make
peer: CMakeFiles/peer.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_8) "Linking C executable peer"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/peer.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/peer.dir/build: peer

.PHONY : CMakeFiles/peer.dir/build

CMakeFiles/peer.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/peer.dir/cmake_clean.cmake
.PHONY : CMakeFiles/peer.dir/clean

CMakeFiles/peer.dir/depend:
	cd "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2" "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2" "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build" "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build" "/mnt/c/Users/Navaljit Ghotra/Uni/praxis2/build/CMakeFiles/peer.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/peer.dir/depend

