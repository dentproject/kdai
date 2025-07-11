#!/bin/bash

# This script checks if DAI compares incoming packets to VLAN_IDs added to the inspeciton list

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
sudo ip netns exec ns1 python3 ../python_helpers/arp_request_and_response_without_vlan_id.py
sudo dmesg -C

echo
echo "=== Running make to build the module ==="
echo
make -C ../..

echo
echo "=== Running make load_with_params to insert the module ==="
echo
make -C ../.. install
echo "10" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect

echo
echo "=== Testing DAI compares VLAN_IDs to added entries ==="
echo
#Send ARP Request with a VLAN that is configured for inspection
sudo ip netns exec ns1 python3 ../python_helpers/arp_request_and_response_with_vlan_id.py
#Send ARP Request with a VLAN that is NOT configured for inspection (Default VLAN_ID)
sudo ip netns exec ns1 python3 ../python_helpers/arp_request_and_response_without_vlan_id.py

sudo dmesg | grep "vlan_id 10 WAS FOUND in the hash table. INSPECTING"
sudo dmesg | grep "vlan_id 1 was NOT in the HASH TABLE"

echo
echo "Test Passed!"          
sudo dmesg -n 7
exit 