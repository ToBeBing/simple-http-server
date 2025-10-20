#!/bin/sh
#
# Use this script to run your program LOCALLY.
#
set -e # Exit early if any commands fail

# 1. Create build directory
mkdir -p build

# 2. Configure CMake. This will use vcpkg to install dependencies if not found.
(
  cd build
  cmake ..
)

# 3. Build the project
cmake --build ./build

# 4. Run the executable
exec ./build/http-server "$@"
