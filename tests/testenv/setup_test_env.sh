#!/bin/bash

# setup_test_env.sh
# This script is meant to setup the testing environment 

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