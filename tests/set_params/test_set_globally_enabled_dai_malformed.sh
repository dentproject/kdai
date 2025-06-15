#!/bin/bash

# This script checks if the kernel module can handle malformed globally_enabled_dai inputs

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
#echo 1 | sudo tee /sys/module/kdai/parameters/globally_enabled_DAI

echo "=== Testing DAI globalldy_enabled_DAI  Entries ==="
# Function to check that the command fails (i.e., invalid input is rejected)
expect_failure() {
    input=$1
    echo "Testing malformed input: '$input'"
    
    set +e  # Temporarily disable exit-on-error
    echo "$input" | sudo tee /sys/module/kdai/parameters/globally_enabled_DAI >/dev/null
    status=$?
    set -e  # Re-enable exit-on-error

    if [ $status -eq 0 ]; then
        echo "Test failed: '$input' was accepted but should have been rejected"
        exit 1
    else
        echo "Test passed: '$input' correctly rejected"
    fi
}

# Run tests
expect_failure 2
expect_failure z
expect_failure -1