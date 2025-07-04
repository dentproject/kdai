
#include "dhcp.h"
#include "trusted_interfaces.h"
#include "rate_limit.h"
#include "vlan.h"
#include "errno.h"
#include "module_params.h"
#include "common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M. Sami GURPINAR <sami.gurpinar@gmail.com>. Edited by Korel Ucpinar <korelucpinar@gmail.com>");
MODULE_DESCRIPTION("kdai(Kernel Dynamic ARP Inspection) is a linux kernel module to defend against arp spoofing");
MODULE_VERSION("1.0"); 

//A Macro used to check if an Ethernet address (addr) is a broadcast address
#define eth_is_bcast(addr) (((addr)[0] & 0xffff) && ((addr)[2] & 0xffff) && ((addr)[4] & 0xffff))

//Two Netfilter Hooks used to capture incoming packets and check if they are either a dhcp or arp packet
static struct nf_hook_ops* bridge_dhcp_hook = NULL;
static struct nf_hook_ops* bridge_arp_hook = NULL;

/**
 * arp_is_valid - Validate ARP packet fields for consistency and correctness
 * @skb: Pointer to the socket buffer containing the packet
 * @ar_op: ARP operation code (e.g., ARP request or reply)
 * @sha: Sender hardware (MAC) address from the ARP message body
 * @sip: Sender IP address from the ARP message body
 * @tha: Target hardware (MAC) address from the ARP message body
 * @tip: Target IP address from the ARP message body
 *
 * This function performs sanity checks on the ARP packet fields to ensure
 * the packet is well-formed and not malformed. It can validate:
 * - That the sender MAC address in the ARP message matches the Ethernet header source MAC 
 * - That sender and target IP addresses are not multicast, loopback, or zero network addresses
 * - That for ARP replies, the target MAC address in the ARP message matches the Ethernet destination MAC
 *
 * Return: SUCCESS (0) if all validations pass,
 *         or negative error codes indicating specific validation failures.
 */
static int arp_is_valid(struct sk_buff* skb, u16 ar_op, unsigned char* sha, 
    u32 sip, unsigned char* tha, u32 tip)  {
    int status = SUCCESS;
    const struct ethhdr* eth;
    unsigned char shaddr[ETH_ALEN],dhaddr[ETH_ALEN];

    eth = eth_hdr(skb);
    memcpy(shaddr, eth->h_source, ETH_ALEN);
    memcpy(dhaddr, eth->h_dest, ETH_ALEN);

    //This is an optional feature that may be uncommented if administrators choose to.
    //On Cisco devices this optional check known as “ip arp inspection validate src-mac”. 
    if (memcmp(sha, shaddr, ETH_ALEN) != 0) {
        //printk(KERN_ERR "kdai: the sender MAC address %pM in the message body is NOT identical to the source MAC address in the Ethernet header %pM\n", sha, shaddr);
        //return -EHWADDR;
    } 

    if (ipv4_is_multicast(sip)) {
        printk(KERN_ERR "kdai: the sender ip address %pI4 is multicast\n", &sip);
        return -EIPADDR;
    }

    if (ipv4_is_loopback(sip)) {
        printk(KERN_ERR "kdai: the sender ip address %pI4 is loopback\n", &sip);
        return -EIPADDR;
    }

    if (ipv4_is_zeronet(sip)) {
        printk(KERN_ERR "kdai: the sender ip address %pI4 is zeronet\n", &sip);
        return -EIPADDR;
    } 

    if (ipv4_is_multicast(tip)) {
        printk(KERN_ERR "kdai: the target ip address %pI4 is multicast\n", &tip);
        return -EIPADDR;
    }

    if (ipv4_is_loopback(tip)) {
        printk(KERN_ERR "kdai: the target ip address %pI4 is loopback\n", &tip);
        return -EIPADDR;
    }

    if (ipv4_is_zeronet(tip)) {
        printk(KERN_ERR "kdai: the target ip address %pI4 is zeronet\n", &tip);
        return -EIPADDR;
    }

    if (ar_op == ARPOP_REPLY) {
        if (memcmp(tha, dhaddr, ETH_ALEN) != 0) {
            printk(KERN_ERR "kdai: the target MAC address %pM in the message body is NOT identical" 
                "to the destination MAC address in the Ethernet header %pM\n", tha, dhaddr);
            return -EHWADDR;
        }  
    }
    return status;
}

/**
 * validate_arp_request - Validate incoming ARP requests for security
 * @priv: Private data pointer 
 * @skb: Pointer to the socket buffer containing the packet
 * @state: Netfilter hook state info 
 * @vlan_id: VLAN ID on which the packet was received
 *
 * This function processes ARP packets hooked at the bridge pre-routing stage.
 * It validates the ARP message by checking:
 *   - ARP header fields (using arp_is_valid)
 *   - Whether the ARP source IP and MAC match known entries in the ARP table
 *   - If static ACL mode is enabled, drops packets not matching static entries
 *   - Otherwise, validates the ARP source against the DHCP snooping table
 * 
 * If validation fails at any stage, the packet is dropped.
 * Packets matching all validation steps are accepted.
 * Special debug bypass for interface "enp0s7".
 *
 * Return:
 *   NF_ACCEPT to allow packet processing to continue
 *   NF_DROP to drop the packet due to validation failure
 */
static unsigned int validate_arp_request(void* priv, struct sk_buff* skb, const struct nf_hook_state* state, u16 vlan_id) {
    
    //Refrence Structure to Standard ARP header used in the linux Kernel
    struct arp_hdr {
        __be16 ar_hrd;         /* hardware address format */
        __be16 ar_pro;         /* protocol address format */
        u8 ar_hln;             /* length of hardware address */
        u8 ar_pln;             /* length of protocol address */
        __be16 ar_op;          /* ARP opcode (command) */
        u8 ar_sha[6];          /* sender hardware address (MAC) */
        u8 ar_sip[4];          /* sender protocol address (IP) */
        u8 ar_tha[6];          /* target hardware address (MAC) */
        u8 ar_tip[4];          /* target protocol address (IP) */
    };

    struct neighbour* hw;
    struct dhcp_snooping_entry* entry;
    struct ethhdr *eth;
    struct arp_hdr *arp;
    unsigned char *sha;
    u32 sip;
    unsigned char *tha;
    u32 tip;
    struct net_device *dev;
    eth = eth_hdr(skb);  // Extract the Ethernet header
    arp = (struct arp_hdr *)(eth + 1);  // Skip past the Ethernet header to get the ARP header
    
    sha = arp->ar_sha;   // Sender MAC address
    sip = *(u32 *)(arp->ar_sip);    // Sender IP address
    tha = arp->ar_tha;   // Target MAC address
    tip = *(u32 *)(arp->ar_tip);    // Target IP address

    dev = skb->dev;

    //For debugging purpouses only
    if(strcmp(dev->name,"enp0s7")==0){
        printk(KERN_INFO "kdai: DEBUGING ONLY Packet was ARP packet for enp0s7. DAI does nothing. ACCEPTING\n\n");
        return NF_ACCEPT;
    } else {
        printk(KERN_ERR "kdai: -- Hooked ARP Packet --\n");
    }

    if (arp_is_valid(skb, ntohs(arp->ar_op), sha, sip, tha, tip) == 0) {
        //Continue Chekcing
        printk(KERN_INFO "kdai: ARP was VALID\n");
    } else {
        printk(KERN_INFO "kdai: ARP was NOT VALID\n");
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;

    }

    printk(KERN_INFO "kdai: ARP request from Source IP: %pI4, came on Interface Name: %s\n", &sip, dev->name);
    printk(KERN_INFO "kdai: Checking an interface on the device\n");
    
    /* This is ARP ACL Match! */
    // Query the ARP table
    // Look up the ARP Table to check if there is an existing ARP entry
    // for the sorce IP address. (The source IP could be real or what the attacker claims to be)
    hw = neigh_lookup(&arp_tbl, &sip, dev);
    if(hw) {
        printk(KERN_INFO "kdai: An entry exists in the ARP Snooping Table for the claimed source IP address.\n");
    } else {
        printk(KERN_INFO "kdai: NO entry exists in the ARP Snooping Table for the claimed source IP address.\n");
    }
    // If we find an entry in the arp table for the source IP address
    // AND the Mac Address of that entry is the same as the mac address from the ARP packet
    if (hw && memcmp(hw->ha, sha, dev->addr_len) == 0) {
        //If they are the same accept the packet
        neigh_release(hw);
        printk(KERN_INFO "kdai: A Known Mac Adress with the same Source IP was the same as the received Mac Address\n");
        printk(KERN_INFO "kdai: ACCEPTING\n\n");
        return NF_ACCEPT;
    }  

    //The entries were different from expected. If Static ACL is configured do not Check DHCP table.
    if (static_ACL_Enabled){
        //Accept packets only that were statically configured
        //Since the previous check failed drop the packet
        printk(KERN_INFO "kdai: Implicit Drop was Added since static_ACL was Enabled\n");
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;
    }
    
    //If an exisitng entry in the ARP table did not match. Check dynamic DHCP Configuraiton
    /* This is ARP DHCP Snooping! */
    // Query the dhcp snooping table
    // Look up the DHCP Snooping Table to check if there is an entry for the claimed
    // source IP address in the table.
    entry = find_dhcp_snooping_entry(sip, vlan_id);
    if(entry) {
        printk(KERN_INFO "kdai: An entry exists in the DHCP Snooping Table for the claimed source IP address.\n");
    } else {
        printk(KERN_INFO "kdai: NO entry exists in the DHCP Snooping Table for the claimed source IP address.\n");
        printk(KERN_INFO "kdai: It is not possible to Validate Source.\n");
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;
    }
    //If we find an entry AND the Mac Address from the DHCP snooping table does not match
    // with the MAC address in the ARP packet ARP spoofing detected.
    if (entry && memcmp(entry->mac, sha, ETH_ALEN) != 0) {
        printk(KERN_INFO "kdai: ARP spoofing detected on %s from %pM\n", dev->name, sha);
        printk(KERN_INFO "ARP spoofing detected on %s, packet droped\n", dev->name);
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;
    } else {
        //The DHCP Snooping table matched.
        printk(KERN_INFO "kdai: -- ACCEPTING ARP PACKET -- \n");
        printk(KERN_INFO "kdai: The DHCP Snooping table matched.\n");
        printk(KERN_INFO "kdai: ACCEPTING\n\n");
        return NF_ACCEPT;
    }    

}

/**
 * is_trusted - check if interface and VLAN combination is trusted
 * @interface_name: interface name string
 * @vlan_id: VLAN ID
 *
 * Returns true if the given interface and VLAN ID are in the trusted list,
 * false otherwise.
 */
static bool is_trusted(const char *interface_name, u16 vlan_id) {
    // Check if the device is trusted using the find_trusted_interface function
    if (find_trusted_interface(interface_name, vlan_id)) {
        //printk(KERN_INFO "\nkdai: Packet was on a trusted interface: %s!!", dev->name);
        return true;  // If the device is trusted, accept the packet
    } else {
        //printk(KERN_INFO "\nkdai: Packet was on an untrusted interface: %s!!", dev->name);
        return false;
    }
}

/**
 * arp_hook_handler - netfilter hook for processing ARP packets
 * @priv: private data pointer 
 * @skb: socket buffer containing the packet
 * @state: netfilter hook state information
 *
 * This function inspects incoming ARP packets on network interfaces,
 * applying Dynamic ARP Inspection (DAI) rules depending on VLAN,
 * global enablement, interface trust, and rate limits. This funciton relies on 
 * validate_arp_request.
 * 
 * Returns NF_ACCEPT to accept the packet or NF_DROP to drop it. 
 */
static unsigned int arp_hook_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {

    struct net_device *dev;
    struct ethhdr * eth;
    u16 vlan_id;

    if (unlikely(!skb)) {
        // Drop if skb is NULL
        printk(KERN_INFO "kdai: SKB was null");
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;  
    }

    dev = skb->dev;
    eth = eth_hdr(skb);

    //Used only for debugging purpouses
    if(strcmp(dev->name,"enp0s7")==0 || strcmp(dev->name,"ma1")==0 ){
        return NF_ACCEPT;
    }

    //1st Did we receive an ARP packet?
    if(ntohs(eth->h_proto) == ETH_P_ARP){
        //YES
        printk(KERN_INFO "kdai: Recieved ARP on %s\n", dev->name);

        //2nd Is Global Inspection enabled
        if(globally_enabled_DAI) {
            //YES
            //Set packet VLAN_id to 1
            vlan_id = 1;
            printk(KERN_INFO "kdai: globally_enabled_DAI was ENABLED\n");
            //Continue checking
        } else {
            //NO
            printk(KERN_INFO "kdai: globally_enabled_DAI was DISABLED\n");

            //Does it have a VLAN?
            if (skb_vlan_tag_present(skb)) {
                //YES
                //Get VLAN ID from the packet
                vlan_id = skb_vlan_tag_get_id(skb);; 
                printk(KERN_INFO "kdai: vlan_id found: %u", vlan_id);
            } else {
                //NO
                //Global was disabled and VLAN_id was not found, default to 1
                printk(KERN_INFO "kdai: No VLAN was found defaulting to 1\n");
                vlan_id = 1;
            }
            //Continue checking
        }
        printk(KERN_INFO "kdai: vlan_id is: %u\n", vlan_id);

        //3rd Is DAI enabled for this VLAN? OR is DAI enabled for all interfaces?
        if(vlan_should_be_inspected(vlan_id) || globally_enabled_DAI) {
            //YES
            //Print Logs
            if(vlan_should_be_inspected(vlan_id)) printk(KERN_INFO "kdai: vlan_id %u WAS FOUND in the hash table. INSPECTING\n", vlan_id);
            if(globally_enabled_DAI) printk(KERN_INFO "kdai: INSPECTING ALL\n");

            //4th Is the interface not trusted?
            if(is_trusted(dev->name,vlan_id) == false){
                //YES
                printk(KERN_INFO "kdai: Interface is UNTRUSTED\n");

                //5th Are we under the rate limit?
                if(!rate_limit_reached(dev->name, vlan_id)) {
                    //YES 
                    //The interface has not hit its limit determine if the ARP request is real.
                    printk(KERN_INFO "kdai: Packet did NOT hit the rate limit!!\n");
                    printk(KERN_INFO "kdai: Validating Packet!!\n");

                    return validate_arp_request(priv, skb, state, vlan_id);

                } else {
                    //NO
                    printk(KERN_INFO "kdai: Packet hit the rate limit.\n");
                    printk(KERN_INFO "kdai: DROPPING\n\n");
                    return NF_DROP;
                }
            } else {
                //NO
                printk(KERN_INFO "kdai: The Interface was Trusted -> ACCEPTING\n");
                printk(KERN_INFO "kdai: ACCEPTING\n\n");
                return NF_ACCEPT;
            }
        } else {
            //NO
            //No need to Inspect packet it was not in our list of VLANS to Inspect
            printk(KERN_INFO "kdai: vlan_id %u was NOT in the HASH TABLE\n", vlan_id);
            printk(KERN_INFO "kdai: ACCEPTING\n\n");
            return NF_ACCEPT;
        }
    } else {
        //NO
        //Do nothing Accept the packet it was not arp
        printk(KERN_INFO "kdai: Packet was not ARP -> ACCEPTING\n");
        printk(KERN_INFO "kdai: ACCEPTING\n\n");
        return NF_ACCEPT;
    }    
}

/**
 * dhcp_hook_handler - netfilter hook for processing DHCP packets
 * @priv: private data pointer 
 * @skb: socket buffer containing the packet
 * @state: netfilter hook state information
 *
 * Processes DHCP packets on the network, updating the DHCP snooping
 * table for lease times, IP-MAC bindings, and handling DHCPACK, DHCPNAK,
 * DHCPRELEASE, and DHCPDECLINE messages. Drops invalid DHCP packets.
 *
 * Returns NF_ACCEPT to accept the packet or NF_DROP to drop it.
 */
static unsigned int dhcp_hook_handler(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct udphdr* udp;
    struct dhcp* payload;
    unsigned char* opt;
    u8 dhcp_packet_type;
    u16  vlan_id;
    u32 lease_time;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
        struct timespec64 ts;
    #else
        struct timespec ts;
    #endif
    struct dhcp_snooping_entry* entry;
    __be16 encapsulated_proto;

    if (unlikely(!skb)) {
        printk(KERN_INFO "kdai: Skb was null\n");
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;
    }

    /* Check if VLAN tag is present */
    if (skb_vlan_tag_present(skb)) {
        u16 vlan_id = skb_vlan_tag_get_id(skb);
        printk(KERN_INFO "kdai: VLAN ID detected: %u\n", vlan_id);

        skb_set_network_header(skb, skb_network_offset(skb));
        skb_set_transport_header(skb, skb_network_offset(skb) + ip_hdr(skb)->ihl * 4);
    }

    encapsulated_proto = vlan_get_protocol(skb);
    if (encapsulated_proto != htons(ETH_P_IP)) {
        printk(KERN_INFO "kdai: Not an IPv4 packet, skipping -> ACCEPTING\n");
        printk(KERN_INFO "kdai: ACCEPTING\n\n");
        return NF_ACCEPT;
    }

    if (skb_transport_offset(skb) + sizeof(struct udphdr) > skb->len) {
        printk(KERN_INFO "kdai: UDP header extends beyond packet. -> DROPPING\n");
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;
    }
    udp = udp_hdr(skb);
    if (!udp) {
        printk(KERN_INFO "kdai: UDP header is NULL -> DROPPING\n");
        printk(KERN_INFO "kdai: DROPPING\n\n");
        return NF_DROP;
    }

    printk(KERN_INFO "kdai: UDP Source Port: %u\n", ntohs(udp->source));
    printk(KERN_INFO "kdai: UDP Destination Port: %u\n", ntohs(udp->dest));

    if (udp->source == htons(DHCP_SERVER_PORT) || udp->source == htons(DHCP_CLIENT_PORT)) {
        printk(KERN_INFO "\nkdai: !! Hooked DHCP PACKET !!");
        payload = (struct dhcp*) ((unsigned char *)udp + sizeof(struct udphdr));
        
        if (dhcp_is_valid(skb) == 0) {
            printk(KERN_INFO "kdai: Saw a valid DHCPACK\n");
            memcpy(&dhcp_packet_type, &payload->bp_options[2], 1);
            printk(KERN_INFO "kdai: DHCP packet type: %u\n", dhcp_packet_type);
            if (skb_vlan_tag_present(skb)) {
                vlan_id = skb_vlan_tag_get_id(skb);
                printk(KERN_INFO "kdai: VLAN ID for DHCPACK was: %d\n", vlan_id);
            } else {
                vlan_id = 1;
                printk(KERN_INFO "kdai: DHCPACK had NO VLAN, defaulting VLAN ID to 1\n");
            }
            switch (dhcp_packet_type) {
                case DHCP_ACK:{
                    for (opt = payload->bp_options; *opt != DHCP_OPTION_END; opt += opt[1] + 2) {
                        if (*opt == DHCP_OPTION_LEASE_TIME) {
                            memcpy(&lease_time, &opt[2], 4);
                            break;
                        }
                    }
                    printk(KERN_INFO "kdai: DHCPACK of %pI4\n", &payload->yiaddr);
                    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
                        ktime_get_real_ts64(&ts);
                    #else
                        getnstimeofday(&ts);
                    #endif
                    entry = find_dhcp_snooping_entry(payload->yiaddr, vlan_id);
                    if (entry) {
                        memcpy(entry->mac, payload->chaddr, ETH_ALEN);
                        entry->lease_time = ntohl(lease_time);
                        entry->expires = ts.tv_sec + ntohl(lease_time);
                        printk(KERN_INFO "kdai: Updated DHCP snooping entry - IP: %pI4, MAC: %pM, Lease Time: %d seconds, Expiry: %d\n",
                            &payload->yiaddr, payload->chaddr, ntohl(lease_time), entry->expires);
                    } else {
                        insert_dhcp_snooping_entry(payload->chaddr, payload->yiaddr, ntohl(lease_time), ts.tv_sec + ntohl(lease_time), vlan_id);
                            //printk(KERN_INFO "kdai: Added new DHCP snooping entry - IP: %pI4, MAC: %pM, Lease Time: %d seconds, Expiry: %lld\n",
                            //    &payload->yiaddr, payload->chaddr, ntohl(lease_time), ts.tv_sec + ntohl(lease_time));
                            printk(KERN_INFO "kdai: Added new DHCP snooping entry - IP: %pI4, MAC: %pM, Lease Time: %d seconds\n",
                                &payload->yiaddr, payload->chaddr, ntohl(lease_time));
                    }
                    break;
                }
                
                case DHCP_NAK:{
                    printk(KERN_INFO "kdai: DHCPNAK of %pI4\n", &payload->yiaddr);
                    entry = find_dhcp_snooping_entry(payload->yiaddr, vlan_id);
                    if (entry) {
                        delete_dhcp_snooping_entry(entry->ip, vlan_id);
                    }
                    break;
                }

                case DHCP_RELEASE:{
                    printk(KERN_INFO "kdai: DHCPRELEASE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr, vlan_id);
                    break;
                }

                case DHCP_DECLINE:{
                    printk(KERN_INFO "kdai: DHCPDECLINE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr, vlan_id);
                    break;
                }
            default:
                printk(KERN_INFO "kdai: DHCP defaulted to break\n");
                break;
            }
      
        } else {
            printk(KERN_INFO "DHCP packet was not valid\n");
            printk(KERN_INFO "kdai: DROPPING\n\n");
            return NF_DROP;
        }
    } else {
        printk(KERN_INFO "(udp->source == htons(DHCP_SERVER_PORT) || udp->source == htons(DHCP_CLIENT_PORT) ) == false -> ACCEPTING\n");
        printk(KERN_INFO "ACCEPTING\n\n");
        return NF_ACCEPT;
    }
    
    printk(KERN_INFO "ACCEPTING\n\n");
    return NF_ACCEPT;
    
}

/**
 * kdai_init - Module initialization function
 *
 * Initializes data structures, parses configuration parameters,
 * registers netfilter hooks for DHCP and ARP, and starts the DHCP
 * cleanup kernel thread.
 *
 * Returns 0 on success or -ENOMEM on failure.
 */
static int __init kdai_init(void) {   

    init_vlan_hash_table();
    parse_vlans(vlans_to_inspect);
    parse_interfaces_and_vlan(trusted_interfaces);

    printk(KERN_INFO "kdai: Module loaded with parameters:\n");
    printk(KERN_INFO "kdai: globally_enabled_DAI=%d\n", globally_enabled_DAI);
    printk(KERN_INFO "kdai: static_ACL_Enabled=%d\n\n", static_ACL_Enabled);
    print_trusted_interface_list();
    print_all_vlans_in_hash();

    bridge_dhcp_hook = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (unlikely(!bridge_dhcp_hook))
        goto err;
    
    bridge_dhcp_hook->hook = (nf_hookfn *) dhcp_hook_handler;         
    bridge_dhcp_hook->hooknum = NF_BR_PRE_ROUTING;          
    bridge_dhcp_hook->pf = NFPROTO_BRIDGE;                  
    bridge_dhcp_hook->priority = NF_BR_PRI_FIRST;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_register_net_hook(&init_net, bridge_dhcp_hook);
    #else
        nf_register_hook(bridge_dhcp_hook);
    #endif
    
    dhcp_thread = kthread_run(dhcp_thread_handler, NULL, "DHCP Thread");
    if(dhcp_thread) {
        printk(KERN_INFO "kdai: DHCP Thread Created Successfully to Remove Expired Entries...\n");
    } else {
        printk(KERN_INFO"kdai: Cannot create kthread\n");
        goto err;
    }

    bridge_arp_hook = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (unlikely(!bridge_arp_hook))
        goto err;
 
    bridge_arp_hook->hook = (nf_hookfn *) arp_hook_handler;  
    bridge_arp_hook->hooknum = NF_BR_PRE_ROUTING;
    bridge_arp_hook->pf = NFPROTO_BRIDGE;
    bridge_arp_hook->priority = NF_BR_PRI_FIRST;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_register_net_hook(&init_net, bridge_arp_hook);
    #else
        nf_register_hook(bridge_arp_hook);
    #endif 

    return 0;   /* success */ 

err:
    if (bridge_dhcp_hook) kfree(bridge_dhcp_hook);
    if(bridge_arp_hook) kfree(bridge_arp_hook);
    return -ENOMEM;    
}

/**
 * kdai_exit - Module cleanup function
 *
 * Unregisters netfilter hooks, stops DHCP cleanup thread,
 * and frees all allocated resources.
 */
static void __exit kdai_exit(void) {

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, bridge_arp_hook);
    #else
        nf_unregister_hook(bridge_arp_hook);
    #endif
    kfree(bridge_arp_hook);

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, bridge_dhcp_hook);
    #else
        nf_unregister_hook(bridge_dhcp_hook);
    #endif
    kfree(bridge_dhcp_hook);

    clean_dhcp_snooping_table();
    kthread_stop(dhcp_thread);
    free_trusted_interface_list();
    free_all_vlan_entries();
    clean_rate_limit_table();

}

module_init(kdai_init);
module_exit(kdai_exit);
