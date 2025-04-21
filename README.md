# kdai: Kernel Dynamic ARP Inspection

**kdai** is a **Loadable Kernel Module (LKM)** designed to enhance network security by detecting and preventing [**ARP cache poisoning attacks**](https://en.wikipedia.org/wiki/ARP_spoofing). The module intercepts all ARP requests and responses passing through a **network bridge**, verifying their authenticity before allowing updates to the bridged system's ARP cache. Below is a detailed summary of the features it supports.

## Features

### ARP Packet Inspection and Logging
Every ARP packet received on a network bridge undergoes a validation process. **kdai** logs invalid ARP packets and **discards those with mismatched or unauthorized IP-to-MAC bindings**, preventing attackers from injecting malicious entries into the ARP caches of bridged devices. Information such as the interfaces where spoofing was detected and the reasons for packet drops are also included.

### DHCP Snooping-Based Validation
To validate incoming ARP packets, **kdai** builds a **dynamic DHCP snooping table** to maintain a trusted list of IP-to-MAC bindings. ARP packets are validated against this table to ensure their legitimacy.

### ARP Access Control Lists (ACLs)
**kdai** also supports **statically configured ARP ACLs**, which are maintained in the local **ARP table**. Administrators can add or remove entries from their local ARP table to explicitly control valid IP-to-MAC pairs. **kdai** can then validate ARP packets against these predefined entries in the ARP table.

### Trusted and Untrusted Interfaces
**kdai** allows each network interface to be assigned a **trust state**:
- **Trusted interfaces** can send and receive ARP packets freely, bypassing validation checks.
- **Untrusted interfaces** undergo Dynamic ARP Inspection 

### Rate Limiting
**kdai** also enforces **rate limiting** to control ARP traffic and mitigate flooding attacks on untrusted interfaces. By default ARP packets on untrusted interfaces are **rate-limited to 15 packets per second**.

## Prerequisites

- Linux system with kernel module support
- GCC (version 5.4.0 or later)

## Installation

### Install
```bash
make install
```
### Test
```bash
$ dmesg | tail -5
[80073.746601] kdai:  DHCP Thread Created Successfully...
[80145.589597] kdai:  DHCPACK of 192.168.1.51
[80160.701525] kdai:  Invalid ARP request from 08:00:27:21:04:c5
[80178.871986] kdai:  ARP spoofing detected on enp0s8 from 08:00:27:21:04:c5
[80550.748553] kdai:  DHCPACK of 192.168.1.42
```
### Uninstall
```bash
make remove
```

### Configuration (Coming Soon)
More detailed configuration instructions will be added soon for ARP ACLs, trusted/untrusted interfaces, rate limiting, and more.

