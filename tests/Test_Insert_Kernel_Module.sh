#!/bin/bash

# Test_Insert_Kernel_Module.sh
# This script checks if the kernel module is insertable

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
make -C ..

echo
echo "=== Running make install to insert the module ==="
echo
make -C .. install

echo
echo "Test Passed!"
echo

echo "Cleaning Up"
sudo dmesg -C
make -C .. remove

exit 0