from scapy.all import ARP, Ether, srp, Dot1Q

def send_arp_request(target_ip, iface, vlan_id=None):
    """Send ARP request and wait for a response using Scapy."""

    # Create an ARP request packet
    arp_request = ARP(pdst=target_ip)

    # Create an Ethernet frame to encapsulate the ARP request
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Add VLAN tagging if VLAN ID is provided
    if vlan_id is not None:
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=vlan_id)

    # Combine the Ethernet frame and ARP request
    arp_request_packet = ether_frame / arp_request

    # Send the ARP request and capture responses
    # scapy.srp returns a tuple of two lists
    answered, unanswered = srp(arp_request_packet, timeout=2, iface=iface, verbose=False)

    # Iterate through the answered list. The answered list itself is a tuple.
    for sent, received in answered:
        print(f"Received ARP response from {received.psrc} ({received.hwsrc})")
        if (received.psrc == target_ip):
            return received
    return None

def send_ARP_handler():
    interface = "veth0"  # Adjust this to your virtual interface srd
    target_ip = "192.168.1.2"  # The IP you expect to reply to ARP requests
    vlan_id = 10

    # Step 1: Send ARP Request and capture response
    print(f"Sending ARP request to {target_ip}...")
    response = send_arp_request(target_ip, interface, vlan_id)

    # Step 2: Validate Test Results
    if response is not None:
        print(f"ARP response received from: {response.psrc}")
    else:
        print("No ARP response received.")

if __name__ == "__main__":
    # Send ARP Message with No VLAN specified
    send_ARP_handler()

