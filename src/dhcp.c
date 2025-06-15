#include "dhcp.h"
#include "errno.h"

LIST_HEAD(dhcp_snooping_list);

DEFINE_SPINLOCK(slock);

struct task_struct* dhcp_thread = NULL;

/**
 * insert_dhcp_snooping_entry - Insert a DHCP snooping entry into the list.
 * @mac: Pointer to the MAC address.
 * @ip: The IP address associated with the DHCP lease.
 * @lease_time: Duration of the lease.
 * @expire_time: Expiration timestamp of the lease.
 * @vlan_id: VLAN ID associated with the entry.
 *
 * This function creates a new DHCP snooping entry with the given parameters and
 * adds it to the global dhcp_snooping_list. The function checks that the VLAN ID
 * is within the valid range (1-4094) before insertion. The list is protected with
 * a spinlock to ensure thread safety.
 *
 * If memory allocation fails, or VLAN ID is invalid, the function returns early.
 */
void insert_dhcp_snooping_entry(u8 *mac, u32 ip, u32 lease_time, u32 expire_time, u16 vlan_id) {
    struct dhcp_snooping_entry* entry;
    unsigned long flags;

    // Check if VLAN ID is within valid range (1-4094)
    if (vlan_id < 1 || vlan_id >= 4095) {
        printk(KERN_INFO "Invalid VLAN ID: %u. Must be between 1 (Default All) and 4094.\n", vlan_id);
        return;
    }

    entry = kmalloc(sizeof(struct dhcp_snooping_entry), GFP_KERNEL);
    if (!entry) {
        printk(KERN_INFO "kdai: kmalloc failed\n");
        return;
    }
    entry->ip = ip;
    entry->lease_time = lease_time;
    entry->expires = expire_time;
    entry->vlan_id = vlan_id;
    memcpy(entry->mac, mac, ETH_ALEN);
    
    spin_lock_irqsave(&slock, flags);
    list_add(&entry->list, &dhcp_snooping_list);
    spin_unlock_irqrestore(&slock, flags);
}


/**
 * find_dhcp_snooping_entry - Find a DHCP snooping entry by IP and VLAN ID.
 * @ip: The IP address to search for.
 * @vlan_id: The VLAN ID associated with the DHCP entry.
 *
 * Searches the global dhcp_snooping_list for an entry matching the given IP and VLAN ID.
 * The list is locked during the search to ensure thread safety.
 *
 * Returns a pointer to the matching dhcp_snooping_entry if found, or NULL if not found.
 */
struct dhcp_snooping_entry* find_dhcp_snooping_entry(u32 ip, u16 vlan_id) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry* entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &dhcp_snooping_list) {
        entry = list_entry(curr, struct dhcp_snooping_entry, list);
        if (entry->ip == ip && entry->vlan_id == vlan_id) {
            spin_unlock_irqrestore(&slock, flags);
            return entry;
        }
    }
    spin_unlock_irqrestore(&slock, flags);
    return NULL;
}

/**
 * delete_dhcp_snooping_entry - Delete a DHCP snooping entry by IP and VLAN ID.
 * @ip: The IP address of the entry to delete.
 * @vlan_id: The VLAN ID associated with the entry to delete.
 *
 * Finds and removes the DHCP snooping entry matching the given IP and VLAN ID
 * from the dhcp_snooping_list. The list is locked during removal to ensure
 * thread safety. Frees the memory allocated for the entry after deletion.
 */
void delete_dhcp_snooping_entry(u32 ip, u16 vlan_id) {
    unsigned long flags;
    struct dhcp_snooping_entry* entry = find_dhcp_snooping_entry(ip, vlan_id);

    if (entry) {
        spin_lock_irqsave(&slock, flags);
        list_del(&entry->list);
        kfree(entry);
        spin_unlock_irqrestore(&slock, flags);
    }   
}

/**
 * clean_dhcp_snooping_table - Remove and free all entries in the DHCP snooping list.
 *
 * Iterates over the dhcp_snooping_list, removing each entry from the list and
 * freeing its associated memory. The list is locked during this operation to
 * ensure thread safety.
 */
void clean_dhcp_snooping_table(void) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry* entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &dhcp_snooping_list) {
        entry = list_entry(curr, struct dhcp_snooping_entry, list);
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&slock, flags);
}

/**
 * dhcp_thread_handler - Kernel thread function to clean expired DHCP snooping entries.
 * @arg: Unused parameter.
 *
 * This function runs in a loop until the kernel thread is requested to stop.
 * It obtains the current time and scans through the dhcp_snooping_list,
 * removing and freeing any entries whose expiration time has passed.
 * The list is locked during the traversal to ensure thread safety.
 * The thread sleeps for 1 second between iterations to reduce CPU usage.
 *
 * Return: Always returns 0.
 */
int dhcp_thread_handler(void *arg) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry* entry;
    unsigned long flags;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
        struct timespec64 ts;
    #else
        struct timespec ts;
    #endif

    while(!kthread_should_stop()) {
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
            ktime_get_real_ts64(&ts);
        #else
            getnstimeofday(&ts);
        #endif
        spin_lock_irqsave(&slock, flags);
        list_for_each_safe(curr, next, &dhcp_snooping_list) {
            entry = list_entry(curr, struct dhcp_snooping_entry, list);
            if (ts.tv_sec >= entry->expires) {
                #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
                    printk(KERN_INFO "kdai:  %pI4 released on %lld\n", &entry->ip, ts.tv_sec);
                #else
                    printk(KERN_INFO "kdai:  %pI4 released on %ld\n", &entry->ip, ts.tv_sec);
                #endif
                list_del(&entry->list);
                kfree(entry);
            }
        }
        spin_unlock_irqrestore(&slock, flags);
        msleep(1000);
    }
    return 0;
}

/**
 * dhcp_is_valid - Validate DHCP packet consistency.
 * @skb: Pointer to the socket buffer containing the DHCP packet.
 *
 * This function checks if the DHCP packet meets certain validity criteria:
 * - For DHCP Discover and Request messages, it verifies that the client hardware address (chaddr)
 *   in the DHCP payload matches the source MAC address in the Ethernet header.
 * - It also checks that the gateway IP address (giaddr) is zero.
 *
 * Returns 0 (SUCCESS) if valid, or a negative error code if validation fails:
 * - -EHWADDR if MAC addresses do not match.
 * - -EIPADDR if giaddr is non-zero.
 */
int dhcp_is_valid(struct sk_buff* skb) {
    int status = SUCCESS;
    struct udphdr* udp;
    struct dhcp* payload;
    struct ethhdr* eth;
    u8 dhcp_packet_type;
    unsigned char shaddr[ETH_ALEN];

    eth = eth_hdr(skb);
    memcpy(shaddr, eth->h_source, ETH_ALEN);

    udp = udp_hdr(skb);
    payload = (struct dhcp*) ((unsigned char*)udp + sizeof(struct udphdr));
    
    memcpy(&dhcp_packet_type, &payload->bp_options[2], 1);

    if ( dhcp_packet_type == DHCP_DISCOVER || dhcp_packet_type == DHCP_REQUEST) {
        if (memcmp(payload->chaddr, shaddr, ETH_ALEN) != 0) {
            printk(KERN_ERR "kdai:  the client MAC address %pM in the message body is NOT identical to the source MAC address in the Ethernet header %pM\n", payload->chaddr, shaddr);
            return -EHWADDR;
        }
    }
    
    if (payload->giaddr != 0) {
        printk(KERN_ERR "kdai:  GW ip address is not zero\n");
        return -EIPADDR;
    }
    
    return status;
}
