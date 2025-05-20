#!/bin/bash

# This script checks if the kernel module is buildable

set -e #Exit immediately if a command exits with a non-zero status

echo
echo "=== Updating Package list ==="
echo
sudo apt-get update

echo
echo "=== Installing build tools ==="
echo
sudo apt-get install -y build-essential

echo
echo "=== Running make to build the module ==="
echo
make -C ../..

echo
echo "Test Passed!"
echo

exit 0