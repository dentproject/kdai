#!/bin/bash

# Test_Load_With_Params_Kernel_Module.sh
# This script checks if the kernel module is loadable with parameters

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
echo "=== Running make load_with_param to prepare the module ==="
echo
make -C .. install

echo "=== Load the kernel module  and Change the parameters==="
echo "1,10" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect

echo
echo "Test Passed!"
echo

echo "Cleaning Up"
sudo dmesg -C
make -C .. remove

exit 0