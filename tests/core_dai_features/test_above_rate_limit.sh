#!/bin/bash

# This script checks if the kernel module drops packets after the defualt 15 packets per second rate limit was exceeded

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
    echo
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
echo "1,10" | sudo tee /sys/module/kdai/parameters/vlans_to_inspect

echo
echo "=== Testing DAI Drops Packets When Rate Limit is Reached ==="
echo
#Send arp packets above the rate limit
sudo ip netns exec ns1 python3 ../python_helpers/send_arp_packets_above_limit.py
sudo dmesg | grep "DROPPING"
sudo dmesg | grep "Packet hit the rate limit."


echo
echo "Test Passed!"     
echo
sudo dmesg -n 7
exit 