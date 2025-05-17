#!/bin/bash

# Test_Below_Rate_Limit.sh
# This script checks if the kernel module does NOT drop packets below the defualt 15 packets per second rate limit

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
    echo
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
echo "=== Testing DAI Accepts Packets when Rate Limit is Not Yet Reached ==="
echo

#Send arp packets above the rate limit
sudo ip netns exec ns1 python3 ./helperPythonFilesForCustomPackets/send_ARP_Packets_Below_Limit.py
if ! dmesg | grep -q "Packet hit the rate limit."; then
    # Pattern not found
    echo "Packet hit the rate limit.' was NOT found"
    
    echo
    echo "Test Passed!"     
    echo
    
    sudo dmesg -n 7
    exit 
else
    # Pattern was found
    echo "Failed: 'Packet hit the rate limit.' WAS found"

    sudo dmesg -n 7
    exit 
fi

