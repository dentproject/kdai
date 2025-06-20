# Dynamic ARP Inspection

As many are aware, the Address Resolution Protocol (ARP) is used to map IP addresses to MAC addresses within a local area network (LAN). However, traditional network stacks do not verify the authenticity of ARP messages. This lack of validation exposes systems to ARP cache poisoning, a technique used to redirect traffic via man-in-the-middle (MITM) attacks, perform denial-of-service (DoS), or facilitate data theft.

Enterprise-grade switches often offer Dynamic ARP Inspection (DAI) as a Layer 2 security feature to mitigate such risks. However, Linux-based networking environments have lacked an equivalent - until now. To fill this gap, we developed **KDAI** (Kernel Dynamic ARP Inspection), a Linux kernel module that implements DAI.

## KDAI

**KDAI** is a Loadable Kernel Module (LKM) for Linux systems that enhances Layer 2 network security by preventing  [**ARP cache poisoning attacks**](https://en.wikipedia.org/wiki/ARP_spoofing). It operates by intercepting ARP messages traversing a Linux bridge and comparing ARP entries against a trusted database of IP-to-Mac address bindings. This database is built dynamically using DHCP Snooping but may also be populated using static ARP entries.

### Key Features of KDAI

### ARP Inspection

KDAI **inspects** all ARP packets received on a Linux bridge in order to log ARP traffic and drop packets with mismatched or unauthorized IP-to-MAC bindings. This inspection helps defend against ARP spoofing and MITM attacks.

---

### DHCP Snooping

Another key feature of KDAI is its DHCP snooping. KDAI builds a **dynamic DHCP snooping table** by monitoring DHCP traffic crosing over a Linux bridge. This table records DHCP requests to form trusted IP-to-MAC address bindings. Incoming ARP packets are validated against this table to ensure their authenticity.

---

### ARP Access Control Lists (ACLs)

KDAI also supports **static ARP ACLs** configured via the system's local ARP table. Administrators can manually add valid IP-to-MAC bindings to compare incoming ARP packets against static ARP entries.

For example, to add a static ARP entry binding the IP address `10.0.0.11` to the MAC address `0c:97:c8:4a:00:01` on interface `enp0s4`, when the module is installed use:

```bash
sudo arp -s 10.0.0.11 0c:97:c8:4a:00:01 -i enp0s4
```

---

### Trusted vs. Untrusted Interfaces

Furthermore, when using KDAI, each interface can be explicitly marked as either:

- **Trusted**: ARP traffic bypasses any checks.
- **Untrusted**: All ARP packets are subject to Dynamic ARP Inspection.

This allows selective enforcement of ARP validation policies across the network.

---

### ARP Rate Limiting

To mitigate ARP flooding, KDAI also enforces **rate limiting**. The default limit is **15 ARP packets per second** on untrusted interfaces.

---

### Per-VLAN Support

KDAI operates on a **per-VLAN basis**, making it suitable for deployment in VLAN-segmented environments. This means that trusted interfaces, rate limits, and inspection rules are all applied independently for each VLAN, allowing for granular enforcement across network segments.

---

## Building and Installing

### Prerequisites

Before building and installing **KDAI**, ensure your system meets the following requirements.

### 1. Kernel Configuration

KDAI requires a Kernel Configuration with the following options enabled (either built-in or as modules):

- **CONFIG_MODULES** – Provides support for loadable kernel modules.
- **CONFIG_IP_NF_ARPFILTER** – Allows ARP packet filtering via Netfilter.
- **CONFIG_BRIDGE_NETFILTER** – Allows IP and ARP filtering on bridged traffic.

If you are unsure whether the following options are enabled try using the following command to view your current Kernel Configuration options:

```bash
zcat /proc/config.gz | grep -E "CONFIG_MODULES|CONFIG_IP_NF_ARPFILTER|CONFIG_BRIDGE_NETFILTER"
```

The Kernel Configurations are enabled if you see the following ouput:

```bash
CONFIG_MODULES=y
CONFIG_IP_NF_ARPFILTER=y
CONFIG_BRIDGE_NETFILTER=y
```

If you do not see the above this means your kernel could be missing one or more of the following configuraitons. In this case, you would need to recompile your kernel with the above either enabled or as loadable modules.

### 2. Install Linux Headers

### Linux Kernel Headers

In order to build the module you need to have your systems Linux kernel headers available.

On most systems, the Linux Kernel headers can be found under:

```bash
/lib/modules/$(uname -r)/build/
```

For example, you should see an output similar to the following:

```bash
root@localhost:~# ls /lib/modules/$(uname -r)/build/
arch  drivers  include  Makefile  Module.symvers  scripts  System.map  tools

```

If the above Kernel Headers are missing, please install them.

On Debian/Ubuntu, you can install the headers with:

```bash
sudo apt-get install linux-headers-$(uname -r)
```

_**NOTE:** If you built **DENT** from [source](https://github.com/dentproject/dentOS), you may locate the headers in the DENT
repo following a similar directory structure as below._

The following is an example built with onl-kernel-5.6-lts-x86-64-all_amd64. The linux kernel headers can be found in the `mbuilds` directory:

```bash
root@localhost:~/dentOS/REPO/buster/extracts/onl-kernel-5.6-lts-x86-64-all_amd64/usr/share/onl/packages/amd64/onl-kernel-5.6-lts-x86-64-all$ ls
kernel-5.6-lts-x86_64-all  mbuilds  mbuilds.zip
```

In order to build the module on DENT copy over the directory content of `mbuilds` to `/lib/modules/$(uname -r)/build/` on to your DENT device.

For example:

```bash
scp -r mbuilds/ user@dent-device:/lib/modules/$(uname -r)/build/
```

### 3. GCC Compiler

Finally ensure you have installed **GCC** version `5.4.0` or later to compile the kernel module.

On most devices you can check your **GCC** version with:

```bash
gcc --version
```

To install **GCC** use:

```bash
sudo apt-get install gcc
```

### Steps for Installation

1. Once the prerequisites are satisfied, go to the associated GitHub repository and clone the repo to your device.

   ```bash
   root@localhost:~# git clone https://github.com/dentproject/kdai.git
   Cloning into 'kdai'...
   remote: Enumerating objects: 898, done.
   remote: Counting objects: 100% (269/269), done.
   remote: Compressing objects: 100% (124/124), done.
   remote: Total 898 (delta 181), reused 200 (delta 131), pack-reused 629 (from 2)
   Receiving objects: 100% (898/898), 317.70 KiB | 24.00 KiB/s, done.
   Resolving deltas: 100% (540/540), done.

   root@localhost:~# ls
   kdai
   ```

2. Build the module using the following command:

   ```bash
   make all
   ```

3. Install the module using the following command:
   ```bash
   make install
   ```

**Congratulations! You have Succesfully built and installed KDAI!**

### Additional commands

1. To unload the module...

```bash
make remove
```

2. To remove all created files

```bash
make clean
```

---
