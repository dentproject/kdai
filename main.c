
#include "dhcp.h"
#include "trustedInterfaces.h"
#include "rate_limit.h"
#include "errno.h"
#include <linux/netfilter_bridge.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M. Sami GURPINAR <sami.gurpinar@gmail.com>. Edited by Korel Ucpinar <korelucpinar@gmail.com>");
MODULE_DESCRIPTION("kdai(Kernel Dynamic ARP Inspection) is a linux kernel module to defend against arp spoofing");
MODULE_VERSION("0.1"); 

#define eth_is_bcast(addr) (((addr)[0] & 0xffff) && ((addr)[2] & 0xffff) && ((addr)[4] & 0xffff))

static struct nf_hook_ops* ipho = NULL;
static struct nf_hook_ops* brho = NULL;

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

static void print_status(int status){
    if(status == 1){
        printk(KERN_INFO "kdai: -- ARP RETURN status was: NF_ACCEPT -- \n\n");
    } else {
        printk(KERN_INFO "kdai: -- ARP RETURN status was: NF_DROP -- \n\n");
    }
}

static unsigned int validate_arp_request(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    
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
    int static_ACL_Enabled;
    struct dhcp_snooping_entry* entry;
    struct ethhdr *eth;
    struct arp_hdr *arp;
    unsigned char *sha;
    u32 sip;
    unsigned char *tha;
    u32 tip;
    struct net_device *dev;
    unsigned int status = NF_ACCEPT;


    eth = eth_hdr(skb);  // Extract the Ethernet header
    if (ntohs(eth->h_proto) != ETH_P_ARP) {
        // Not an ARP packet
        printk(KERN_INFO "kdai: Packet was NOT an ARP packet. DAI does nothing. Accepting\n");
        return NF_ACCEPT;
    }
    arp = (struct arp_hdr *)(eth + 1);  // Skip past the Ethernet header to get the ARP header
    
    sha = arp->ar_sha;   // Sender MAC address
    sip = *(u32 *)(arp->ar_sip);    // Sender IP address
    tha = arp->ar_tha;   // Target MAC address
    tip = *(u32 *)(arp->ar_tip);    // Target IP address

    dev = skb->dev;

    if (unlikely(!skb)) {
        // Drop if skb is NULL
        return NF_DROP;  
    }

    //For debugging purpouses only
    if(strcmp(dev->name,"enp0s7")==0){
        printk(KERN_INFO "kdai: Packet was ARP packet for enp0s7. DAI does nothing. Accepting\n");
        return NF_ACCEPT;
    } else {
        printk(KERN_ERR "kdai: -- Hooked ARP Packet --\n");
    }

    if (arp_is_valid(skb, ntohs(arp->ar_op), sha, sip, tha, tip) == 0) {
        //Continue Chekcing
        printk(KERN_INFO "kdai: ARP was VALID\n");
    } else {
        printk(KERN_INFO "kdai: ARP was NOT VALID\n");
        status = NF_DROP;
        print_status(status);
        return status;
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
        printk(KERN_INFO "kdai: A Known Mac Adress with the same Source IP was the same as the received Mac Address\n");
        //If they are the same accept the packet
        status = NF_ACCEPT;
        neigh_release(hw);
        print_status(status);
        return status;
    }  

    //The entries were different from expected. If Static ACL is configured do not Check DHCP table.
    
    static_ACL_Enabled = 0; // Default is false
    if (static_ACL_Enabled){
        //Accept packets only that were statically configured
        //Since the previous check failed drop the packet
        printk(KERN_INFO "kdai: Implicit Drop was Added since static_ACL was Enabled\n");
        status = NF_DROP;
        print_status(status);
        return status;
    }
    
    //If an exisitng entry in the ARP table did not match. Check dynamic DHCP Configuraiton

    // Query the dhcp snooping table
    // Look up the DHCP Snooping Table to check if there is an entry for the claimed
    // source IP address in the table.
    entry = find_dhcp_snooping_entry(sip);
    if(entry) {
        printk(KERN_INFO "kdai: An entry exists in the DHCP Snooping Table for the claimed source IP address.\n");
    } else {
        printk(KERN_INFO "kdai: NO entry exists in the DHCP Snooping Table for the claimed source IP address.\n");
        printk(KERN_INFO "kdai: It is not possible to Validate Source.\n");
        status = NF_DROP;
        print_status(status);
        return status;
    }

    //If we find an entry AND the Mac Address from the DHCP snooping table does not match
    // with the MAC address in the ARP packet ARP spoofing detected.
    if (entry && memcmp(entry->mac, sha, ETH_ALEN) != 0) {
        printk(KERN_INFO "kdai: ARP spoofing detected on %s from %pM\n", dev->name, sha);
        printk(KERN_INFO "ARP spoofing detected on %s, packet droped", dev->name);
        status = NF_DROP;
        print_status(status);
        return status;
    } else {
        //The DHCP Snooping table matched.
        printk(KERN_INFO "kdai: -- ACCEPTING ARP PACKET -- \n");
        status = NF_ACCEPT;
        print_status(status);
        return status;
    }    

    print_status(status);
    return status;
}

static bool is_trusted(struct sk_buff* skb) {
    struct net_device *dev;
    dev = skb->dev;

    // Check if the device is trusted using the find_trusted_interface function
    if (find_trusted_interface(dev->name)) {
        //printk(KERN_INFO "\nkdai: Packet was on a trusted interface: %s!!", dev->name);
        return true;  // If the device is trusted, accept the packet
    } else {
        //printk(KERN_INFO "\nkdai: Packet was on an untrusted interface: %s!!", dev->name);
        return false;
    }
}

static unsigned int bridge_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct net_device *dev;
    dev = skb->dev;

    //Used only for debugging purpouses
    if(strcmp(dev->name,"enp0s7")==0 || strcmp(dev->name,"ma1")==0 ){
        return NF_ACCEPT;
    }

    //If the interface is trusted skip any calculations and accept the packet
    if(is_trusted(skb)){
        return NF_ACCEPT;
    } else {
        //Else the interface is not trusted
        //Ensure it is is an ARP packet before performing rate limiting
        struct ethhdr * eth = eth_hdr(skb);
        if(ntohs(eth->h_proto) == ETH_P_ARP){
            printk(KERN_INFO "kdai: Recieved ARP on %s\n", dev->name);
            printk(KERN_INFO "kdai: Checking if we hit the rate limit for %s!!\n", dev->name);
            //If the untrusted interface has hit its rate limit, the packet should be dropped
            if(rate_limit_reached(skb)) {
                printk(KERN_INFO "kdai: Packet hit the rate limit...dropping!!\n");
                return NF_DROP;
            } else {
            //Else the interface has not hit its limit determine if the ARP request is real.
                printk(KERN_INFO "kdai: Packet did NOT hit the rate limit!!\n");
                printk(KERN_INFO "kdai: Validating Packet!!\n");
                return validate_arp_request(priv, skb, state);
            }
        } else {
            //Do nothing Accept the packet it was not arp
            //printk(KERN_INFO "kdai: Accept Packet it was not ARP!!\n");
            return NF_ACCEPT;
        }
    }
}

static unsigned int ip_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct udphdr* udp;
    struct dhcp* payload;
    unsigned char* opt;
    u8 dhcp_packet_type;
    u32 lease_time;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
        struct timespec64 ts;
    #else
        struct timespec ts;
    #endif
    struct dhcp_snooping_entry* entry;
    unsigned int status = NF_ACCEPT;

    if (unlikely(!skb))
        return NF_DROP;

    udp = udp_hdr(skb);
    
    if (udp->source == htons(DHCP_SERVER_PORT) || udp->source == htons(DHCP_CLIENT_PORT)) {
        printk(KERN_INFO "\nkdai: !! Hooked DHCP PACKET !!");
        payload = (struct dhcp*) ((unsigned char *)udp + sizeof(struct udphdr));
        
        if (dhcp_is_valid(skb) == 0) {
            printk(KERN_INFO "kdai: Saw a valid DHCPACK\n");
            memcpy(&dhcp_packet_type, &payload->bp_options[2], 1);
            printk(KERN_INFO "kdai: DHCP packet type: %u\n", dhcp_packet_type);
            
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
                    entry = find_dhcp_snooping_entry(payload->yiaddr);
                    if (entry) {
                        memcpy(entry->mac, payload->chaddr, ETH_ALEN);
                        entry->lease_time = ntohl(lease_time);
                        entry->expires = ts.tv_sec + ntohl(lease_time);
                        printk(KERN_INFO "kdai: Updated DHCP snooping entry - IP: %pI4, MAC: %pM, Lease Time: %d seconds, Expiry: %d\n",
                            &payload->yiaddr, payload->chaddr, ntohl(lease_time), entry->expires);
                    } else {
                        insert_dhcp_snooping_entry(
                            payload->chaddr, payload->yiaddr, ntohl(lease_time), ts.tv_sec + ntohl(lease_time));
                            printk(KERN_INFO "kdai: Added new DHCP snooping entry - IP: %pI4, MAC: %pM, Lease Time: %d seconds, Expiry: %lld\n",
                                &payload->yiaddr, payload->chaddr, ntohl(lease_time), ts.tv_sec + ntohl(lease_time));
                    }
                    break;
                }
                
                case DHCP_NAK:{
                    printk(KERN_INFO "kdai: DHCPNAK of %pI4\n", &payload->yiaddr);
                    entry = find_dhcp_snooping_entry(payload->yiaddr);
                    if (entry) {
                        delete_dhcp_snooping_entry(entry->ip);
                    }
                    break;
                }

                case DHCP_RELEASE:{
                    printk(KERN_INFO "kdai: DHCPRELEASE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr);
                    break;
                }

                case DHCP_DECLINE:{
                    printk(KERN_INFO "kdai: DHCPDECLINE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr);
                    break;
                }
            default:
                printk(KERN_INFO "kdai: DHCP defaulted to break\n");
                break;
            }
      
        } else status = NF_DROP;
    }
   
    return status;
}


static int __init kdai_init(void) {
    
    //populate_trusted_interface_list();
    //insert_trusted_interface("enp0s4");
    //insert_trusted_interface("ma1");
    print_trusted_interface_list();
    /*
    if(find_trusted_interface("enp0s4")) {
        printk(KERN_INFO "Found enp0s4 in the list");
    } else {
        printk(KERN_INFO "Did not find enp0s4 in the list");
    }
    */
   
     /*Initialize Generic Hook for rate limiting all Bridged Traffic*/
     brho = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
     if (unlikely(!brho))
         goto err;
 
     brho->hook = (nf_hookfn *) bridge_hook;  
     brho->hooknum = NF_BR_PRE_ROUTING;
     brho->pf = NFPROTO_BRIDGE;
     brho->priority = NF_BR_PRI_FIRST;
     #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
     nf_register_net_hook(&init_net, brho);
     #else
         nf_register_hook(brho);
     #endif 

    /* Initialize ip netfilter hook */
    ipho = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (unlikely(!ipho))
        goto err;
    
    ipho->hook = (nf_hookfn *) ip_hook;         /* hook function */
    ipho->hooknum = NF_BR_PRE_ROUTING;          /* received packets */
    ipho->pf = NFPROTO_BRIDGE;                  /* IP */
    ipho->priority = NF_BR_PRI_FIRST;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_register_net_hook(&init_net, ipho);
    #else
        nf_register_hook(ipho);
    #endif
    
    dhcp_thread = kthread_run(dhcp_thread_handler, NULL, "DHCP Thread");
    if(dhcp_thread) {
        printk(KERN_INFO"kdai: DHCP Thread Created Successfully...\n");
    } else {
        printk(KERN_INFO"kdai: Cannot create kthread\n");
        goto err;
    }
    return 0;   /* success */ 
err:
    if (ipho) kfree(ipho);
    if(brho) kfree(brho);
    return -ENOMEM;    
}


static void __exit kdai_exit(void) {

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, brho);
    #else
        nf_unregister_hook(brho);
    #endif
    kfree(brho);

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, ipho);
    #else
        nf_unregister_hook(ipho);
    #endif
    kfree(ipho);

    clean_dhcp_snooping_table();
    kthread_stop(dhcp_thread);
    free_trusted_interface_list();

}

module_init(kdai_init);
module_exit(kdai_exit);
