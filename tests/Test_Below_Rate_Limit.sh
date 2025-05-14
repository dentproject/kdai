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

echo
echo "=== Updating Package list ==="
echo
sudo apt-get update

echo
echo "=== Installing build tools ==="
echo
sudo apt-get install -y build-essential

echo
echo "=== Installing Networking tools ==="
echo
sudo sudo apt install -y bridge-utils && sudo apt install -y iproute2

echo
echo "=== Installing Python Dependencies ==="
echo
sudo apt-get update
sudo apt-get install -y python3-pip
sudo pip3 install scapy
sudo apt-get install -y dsniff 

echo
echo "=== Create Bridges, Virtual Interfaces, and Namespaces ==="
echo
sudo ip link add name br1 type bridge
sudo ip link add veth0 type veth peer name veth1
sudo ifconfig veth0 hw ether e2:c8:14:a6:4f:ed
sudo ip link add veth2 type veth peer name veth3
sudo ifconfig veth3 hw ether  3a:18:70:ca:91:b2
sudo ip netns add ns1
sudo ip netns add ns2

echo
echo "=== Assigning Interfaces to Namespaces ==="
echo
sudo ip link set veth0 netns ns1
sudo ip link set veth3 netns ns2

echo
echo "=== Attaching Interfaces to Bridge ==="
echo
sudo ip link set veth1 master br1
sudo ip link set veth2 master br1

echo
echo "=== Setting Up Namespace Test Enviornment ==="
echo
sudo ip netns exec ns1 ip addr add 192.168.1.1/24 dev veth0
sudo ip netns exec ns2 ip addr add 192.168.1.2/24 dev veth3

echo
echo "=== Bringing Up Interfaces ==="
echo
sudo ip link set br1 up
sudo ip link set veth1 up
sudo ip link set veth2 up
sudo ip netns exec ns1 ip link set veth0 up
sudo ip netns exec ns2 ip link set veth3 up
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up

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
make -C .. load_with_params
sudo modprobe kdai vlans_to_inspect="0,10"

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

