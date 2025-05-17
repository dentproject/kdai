#!/bin/bash

# Test_Static_Entry_Exists_In_The_ARP_Table.sh
# This script checks if the kernel module Accepts packets with a static arp entry in the ARP Table

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
sudo echo "1,10" > /sys/module/kdai/parameters/vlans_to_inspect

echo
echo "=== Testing Static Arp Entry In ARP Table ==="
echo
sudo ip netns exec ns1 ip link set veth0 down
sudo ip netns exec ns1 sudo ifconfig veth0 hw ether e2:c8:14:a6:4f:ed
sudo ip netns exec ns1 ip link set veth0 up
sudo ip netns exec ns2 ip link set veth3 down
sudo ip netns exec ns2 sudo ifconfig veth3 hw ether  3a:18:70:ca:91:b2
sudo ip netns exec ns2 ip link set veth3 up
sudo arp -s 192.168.1.1 e2:c8:14:a6:4f:ed -i veth1
sudo arp -s 192.168.1.2 3a:18:70:ca:91:b2 -i veth2
#Test communicaiton after static entries were added
sudo ip netns exec ns1 python3 ./helperPythonFilesForCustomPackets/ARP_Request_And_Response_With_VLAN_ID.py

ARP_DROP_STATUS=$(sudo dmesg | grep "ACCEPTING")
ARP_EXIT_STATUS=$(sudo dmesg | grep "A Known Mac Adress with the same Source IP was the same as the received Mac Address")


echo
echo "Test Passed!"          
sudo dmesg -n 7
exit 0