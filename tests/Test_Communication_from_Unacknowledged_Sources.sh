#!/bin/bash

# Test_Communication_from_Unacknowledged_Sources.sh.sh
# This script checks if the kernel module Accepts packets that were NOT added to the DHCP snooping table

set -euo pipefail  # Safer bash: treat unset vars as errors

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
    make -C .. remove || true

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
sudo dmesg -C
sudo dmesg -n 3
cleanup

sudo ./testenv/setup_test_env.sh

echo
echo "=== Ensure Working Test Environment ==="
echo
sudo ip netns exec ns1 python3 ./helperPythonFilesForCustomPackets/ARP_Request_And_Response_Without_VLAN_ID.py
sudo dmesg -C

echo
echo "=== Running make to build the module ==="
echo
make -C ..

echo
echo "=== Running make load_with_params to insert the module ==="
echo
make -C .. install
echo "1,10" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect

echo
echo "=== Testing DAI Filtering From Unacknowledged Sources ==="
echo
#Send arp request without first being added to the DHCP or Static ARP table
sudo ip netns exec ns1 python3 ./helperPythonFilesForCustomPackets/ARP_Request_And_Response_With_VLAN_ID.py

ARP_DROP_STATUS=$(sudo dmesg | tail -n 20 | grep "DROPPING")
ARP_EXIT_STATUS=$(sudo dmesg | tail -n 20 | grep "It is not possible to Validate Source.")


echo
echo "Test Passed!"          
sudo dmesg -n 7
exit 0