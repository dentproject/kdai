# Dynamic ARP Inspection

The Address Resolution Protocol (ARP) lacks built-in validation, making networks vulnerable to [**ARP cache poisoning**](https://en.wikipedia.org/wiki/ARP_spoofing) and enabling man-in-the-middle or denial-of-service attacks. Enterprise-grade switches often offer Dynamic ARP Inspection (DAI) as a Layer 2 security feature to mitigate such risks. However, Linux-based networking environments have lacked an equivalent - until now. To fill this gap, we developed **KDAI** (Kernel Dynamic ARP Inspection), a Linux kernel module that implements DAI.

## KDAI

**KDAI** is a Loadable Kernel Module (LKM) for Linux systems that enhances Layer 2 network security by preventing **ARP cache poisoning**. It operates by intercepting ARP messages traversing a Linux bridge and comparing ARP entries against a trusted database of IP-to-Mac address bindings. This database is built dynamically using DHCP Snooping but may also be populated using static ARP entries.

### Key Features of KDAI

- ### ARP Inspection
  KDAI **inspects** all ARP packets received on a Linux bridge in order to log ARP traffic and drop packets with mismatched or unauthorized IP-to-MAC bindings. This inspection helps defend against ARP spoofing and MITM attacks.

- ### DHCP Snooping
  Another key feature of KDAI is its DHCP snooping. KDAI builds a **dynamic DHCP snooping table** by monitoring DHCP traffic crosing over a Linux bridge. This table records DHCP requests to form trusted IP-to-MAC address bindings. Incoming ARP packets are validated against this table to ensure their authenticity.

- ### ARP Access Control Lists (ACLs)
  KDAI also supports **static ARP ACLs** configured via the system's local ARP table. Administrators can manually add valid IP-to-MAC bindings to compare incoming ARP packets against static ARP entries.

- ### Trusted vs. Untrusted Interfaces
  Furthermore, when using KDAI, each interface can be explicitly marked as either:
   - **Trusted**: ARP traffic bypasses any checks.
   - **Untrusted**: All ARP packets are subject to Dynamic ARP Inspection.
  
- ### ARP Rate Limiting
  To mitigate ARP flooding, KDAI also enforces **rate limiting**. The default limit is **15 ARP packets per second** on untrusted interfaces.

- ### Per-VLAN Support
  KDAI operates on a **per-VLAN basis**, making it suitable for deployment in VLAN-segmented environments. This means that trusted interfaces, rate limits, and inspection rules are all applied independently for each VLAN, allowing for granular enforcement across network segments.

## Building

### Prerequisites

Before building **KDAI**, ensure your system meets the following requirements.

#### 1. Kernel Configuration Requirement

   KDAI requires a Kernel Configuration with the following options enabled (either built-in or as modules):
   
   - **CONFIG_MODULES** – Provides support for loadable kernel modules.
   - **CONFIG_IP_NF_ARPFILTER** – Allows ARP packet filtering via Netfilter.
   - **CONFIG_BRIDGE_NETFILTER** – Allows IP and ARP filtering on bridged traffic.
   
   If you do not have these Kernel Configurations you may need to recompile your kernel with the above either enabled or as loadable modules

#### 2. Linux Header Requirement

   In order to build the module you need to have your systems Linux kernel headers available.
   
   On Debian/Ubuntu, you can install the headers with:
   
   ```bash
   sudo apt-get install linux-headers-$(uname -r)
   ```
   
   _**NOTE:** If you built **DENT** from [source](https://github.com/dentproject/dentOS), you may locate the headers in the DENT
   repo following a similar directory structure as below._
   
   The following is an example built with `onl-kernel-5.6-lts-x86-64-all_amd64`. The linux kernel headers can be found in the `mbuilds` directory:
   
   ```bash
   root@localhost:~/dentOS/REPO/buster/extracts/onl-kernel-5.6-lts-x86-64-all_amd64/usr/share/onl/packages/amd64/onl-kernel-5.6-lts-x86-64-all$ ls
   kernel-5.6-lts-x86_64-all  mbuilds  mbuilds.zip
   ```
   
   In order to build the module on DENT copy over the directory content of `mbuilds` to `/lib/modules/$(uname -r)/build/` on to your DENT device.
   
#### 3. GCC Compiler Requirement

Ensure you have installed **GCC** version `5.4.0` or later to compile the kernel module.

## Installation

Once the prerequisites are satisfied...

**1. Clone the Repo to Your Device and Change Directories:**
   ```bash
   git clone https://github.com/dentproject/kdai.git
   cd kdai
   ```

**2. Build the Module Using the Following Command:**
   ```bash
   make all
   ```

**3. Install the Module Using the Following Command:**
   ```bash
   make install
   ```

**Congratulations! You have Succesfully built and installed KDAI!**


### Additional commands

**1. To Unload the Module:**

```bash
make remove
```

**2. To Remove All Created Files:**

```bash
make clean
```

## Tests
All tests are bash scripts and as a result can be run with `./${script_name}`

For example, to run `./test_arp_poisoning.sh` switch to the associated test directory:
```bash
cd kdai/tests/core_dai_features
```

Ensure the test script is executable and the script for the testing environment is executable:
```bash
chmod +x ../testenv/setup_test_env.sh
chmod +x ./test_arp_poisoning.sh
```

Finally run the test with:
```bash
./test_arp_poisoning.sh
```

Ex.
```bash
root@localhost:~/kdai/tests/core_dai_features# ./test_arp_poisoning.sh
[...]
[14524.984472] kdai: ARP spoofing detected on veth1 from e2:c8:14:a6:4f:ed
[14524.984473] ARP spoofing detected on veth1, packet droped

Test Passed!

=== Cleaning Up ===
[...]
```

To see KDAI logs use:
```bash
dmesg
```

## Demo Video

Watch KDAI in action blocking an ARP poisoning attack in this silent demonstration:

[Kernel Dynamic ARP Inspection Demo](https://www.youtube.com/watch?v=-t_kD8r_B0Q)

_This video shows how KDAI detects and drops malicious ARP packets to prevent man-in-the-middle attacks._
