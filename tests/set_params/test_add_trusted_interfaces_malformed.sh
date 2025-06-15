#!/bin/bash

# This script checks if the kernel module can handle malformed Trusted Interface Inputs

set -euo pipefail  #treat unset vars as errors

# Track current command for debugging
last_command=""
current_command=""
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG

# Log which command caused exit
trap 'echo ""; echo "TEST FAILED - Script exited during: \"$last_command\"" >&2' ERR

# Define the cleanup function
cleanup() {
    echo
    echo "=== Cleaning Up ==="
    echo
    make -C ../.. remove || true

    sudo ip netns exec ns1 ip link set lo down || true
    sudo ip netns exec ns2 ip link set lo down || true
    sudo ip netns exec ns1 ip link set veth0 down || true
    sudo ip netns exec ns2 ip link set veth3 down || true
    sudo ip link set veth1 down || true
    sudo ip link set veth2 down || true
    sudo ip link set br1 down || true

    sudo ip netns delete ns1 || true
    sudo ip netns delete ns2 || true
    sudo ip link delete br1 || true

    echo "=== Clean-up Complete ==="
}

# Always run cleanup on exit (normal or error)
trap cleanup EXIT

cleanup
sudo dmesg -C
sudo dmesg -n 3

sudo ../testenv/setup_test_env.sh

echo
echo "=== Ensure Working Test Environment ==="
echo
#sudo ip netns exec ns1 python3 ../python_helpers/arp_request_and_response_without_vlan_id.py
sudo dmesg -C

echo
echo "=== Running make to build the module ==="
echo
make -C ../..

echo
echo "=== Running make load_with_params to insert the module ==="
echo
make -C ../.. install
# Valid input for context
#echo "veth1:1" | sudo tee /sys/module/kdai/parameters/trusted_interfaces
#echo -n "0" | sudo tee /sys/module/kdai/parameters/trusted_interfaces           # Empty input (remove the newline character)

# Malformed / edge-case inputs
echo -n "veth1" | sudo tee /sys/module/kdai/parameters/trusted_interfaces         # Missing colon + value
echo -n ":1" | sudo tee /sys/module/kdai/parameters/trusted_interfaces           # Missing interface name
echo -n "veth1:" | sudo tee /sys/module/kdai/parameters/trusted_interfaces       # Missing value
echo -n "veth1::1" | sudo tee /sys/module/kdai/parameters/trusted_interfaces     # Extra colon
echo -n "veth1:abc" | sudo tee /sys/module/kdai/parameters/trusted_interfaces    # Non-numeric value
echo -n "veth1:-1" | sudo tee /sys/module/kdai/parameters/trusted_interfaces     # Negative value (if invalid)
echo -n "veth1:1:extra" | sudo tee /sys/module/kdai/parameters/trusted_interfaces # Too many fields
echo -n "veth1:1,veth2" | sudo tee /sys/module/kdai/parameters/trusted_interfaces # Mixed valid/invalid
echo "@!veth1:1" | sudo tee /sys/module/kdai/parameters/trusted_interfaces    # Invalid interface characters
echo

echo "=== Testing DAI Adds Trusted Interface to Entries ==="
echo
sudo dmesg | grep -E 'Invalid Format \(Expected: eth0:1\), Input Recieved: "veth1"'
sudo dmesg | grep -E 'Interface not found: ""'
sudo dmesg | grep -E 'Input Format Error for Trusted Interface \(Expected: eth0:1\)' #Check for "veth1:" "veth1::1" "veth1:abc" "veth1:-1" "veth1:1:extra"
sudo dmesg | grep -E 'Invalid Format \(Expected: eth0:1\), Input Recieved: "veth1:1,veth2"'
sudo dmesg | grep -E 'Interface not found: "@!veth1"'


echo
echo "Test Passed!"          
sudo dmesg -n 7
echo

exit 