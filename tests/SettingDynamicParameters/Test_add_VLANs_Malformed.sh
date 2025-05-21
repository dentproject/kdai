#!/bin/bash

# This script checks if the kernel module can handle malformed Trusted Interface Input

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

#sudo ../testenv/setup_test_env.sh

echo
echo "=== Ensure Working Test Environment ==="
echo
#sudo ip netns exec ns1 python3 ../helperPythonFilesForCustomPackets/ARP_Request_And_Response_Without_VLAN_ID.py
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
# echo "10,20" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect
#echo -n "clear" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect           # Empty input (remove the newline character)

# Malformed / edge-case inputs
echo -n "10,abc,30" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect # VLAN ID with non-numeric characters
echo -n ",,," | sudo tee /sys/module/kdai/parameters/vlans_to_inspect # Multiple commas without values
echo -n " 10 , 20 " | sudo tee /sys/module/kdai/parameters/vlans_to_inspect # VLAN ID with leading or trailing spaces
echo -n "10,20," | sudo tee /sys/module/kdai/parameters/vlans_to_inspect # Trailing comma
echo -n "10   ,  20" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect # Excessive spaces around commas
echo -n "-10,20" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect # Negative VLAN ID

echo

echo "=== Testing DAI Adds Trusted Interface to Entries ==="
echo
#sudo dmesg | grep -E 'Clearing VLANs To Inspect list'
sudo dmesg | grep -E 'Invalid VLAN_ID: "abc"'
sudo dmesg | grep -E 'Invalid VLAN_ID: ""' # VLAN ID with leading or trailing spaces,  Multiple commas without values
sudo dmesg | grep -E 'Invalid VLAN_ID: " 10 "'
sudo dmesg | grep -E 'Invalid VLAN_ID: " 20 "'
sudo dmesg | grep -E 'Invalid VLAN_ID: "10   "'
sudo dmesg | grep -E 'Invalid VLAN_ID: "  20"'
sudo dmesg | grep -E 'Invalid VLAN_ID: "-10"'


echo
echo "Test Passed!"          
sudo dmesg -n 7
echo

exit 