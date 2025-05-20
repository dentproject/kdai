#!/bin/bash

# Test_globally_enabled_DAI.sh
# This script checks if the kernel module inspects all packets when globally_enabled_DAI is true

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
sudo ip netns exec ns1 python3 ../helperPythonFilesForCustomPackets/ARP_Request_And_Response_Without_VLAN_ID.py
sudo dmesg -C

echo
echo "=== Running make to build the module ==="
echo
make -C ../..

echo
echo "=== Running make load_with_params to insert the module ==="
echo
make -C ../.. install
echo "1,10" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect
echo 1 | sudo tee /sys/module/kdai/parameters/globally_enabled_DAI

echo
echo "=== Testing DAI Inspects all packets ==="
echo
# Create and send the switch a Cusotm DHCP packet ACK for both 192.168.1.1 and 192.168.1.2 with VLAN_ID 10
sudo ip netns exec ns1 python3 ../helperPythonFilesForCustomPackets/DHCP_with_VLAN_10.py
#Send and ARP Request and wait for a Response
sudo ip netns exec ns1 python3 ../helperPythonFilesForCustomPackets/ARP_Request_And_Response_With_VLAN_ID.py

sudo dmesg | grep "globally_enabled_DAI was ENABLED"


echo
echo "Test Passed!"          
sudo dmesg -n 7
exit 