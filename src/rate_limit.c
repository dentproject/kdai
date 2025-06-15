#include "rate_limit.h"

#define RATE_LIMIT_WINDOW 1000  // in milliseconds (1000 = 1 second)
#define MAX_PACKETS_PER_WINDOW 15  // maximum packets per window. By default, the rate for untrusted interfaces is 15 packets per second (pps)

LIST_HEAD(rate_limit_list);
DEFINE_SPINLOCK(rate_lock);

/**
 * get_rate_limit_entry - Search for a rate limit entry by interface name.
 * @iface_name: The name of the interface to look up.
 * @vlan_id: The vlan_id to match for Dynamic Arp Inspeciton.
 *
 * This function looks through the rate_limit_list for an entry matching the given
 * interface name. It uses a spinlock to ensure safe access in concurrent contexts.
 *
 * Return: Pointer to the matching rate_limit_entry if found, otherwise NULL.
 */
static struct rate_limit_entry* get_rate_limit_entry(const char *iface_name, u16 vlan_id) {
    struct rate_limit_entry *entry;
    unsigned long flags;

    //Acquire the spin lock to safely traverse the lsit
    spin_lock_irqsave(&rate_lock, flags);

    //Iterate through the list to find a matching interface name and vlan id
    list_for_each_entry(entry, &rate_limit_list, list) {
        if(strncmp(entry->iface_name, iface_name, IFNAMSIZ) == 0 && entry->vlan_id == vlan_id){
            spin_unlock_irqrestore(&rate_lock, flags);
            return entry;
        }
    }
    spin_unlock_irqrestore(&rate_lock, flags);
    //We did not find an entry return null
    return NULL;
}

/**
 * create_rate_limit_entry - Create and insert a new rate limit entry.
 * @iface_name: The name of the interface to add.
 * @vlan_id: The vlan_id to match for Dynamic Arp Inspeciton.
 *
 * This function allocates and initializes a new rate limit entry for a network
 * interface if one does not already exist. It adds the new entry to the
 * global rate_limit_list under a spinlock to ensure thread safety.
 *
 * Return: Pointer to the new entry on success, or NULL if it already exists, allocation fails, or VLAN was invalid.
 */
static struct rate_limit_entry* create_rate_limit_entry(const char *iface_name, u16 vlan_id) {
    struct rate_limit_entry *entry;
    unsigned long flags;

    //If the entry already exists return null
    entry = get_rate_limit_entry(iface_name, vlan_id);
    if(entry != NULL){
        return NULL;
    }

    // Check if VLAN ID is within valid range (1-4094)
    if (vlan_id < 1 || vlan_id >= 4095) {
        printk(KERN_INFO "Invalid VLAN ID: %u. Must be between 1 (Default All) and 4094.\n", vlan_id);
        return NULL;
    }

    //Allocate and initialize the size of a new entry
    entry = kmalloc(sizeof(struct rate_limit_entry), GFP_KERNEL);
    if(entry == NULL){
        printk(KERN_INFO "kdai kmalloc failed\n");
        return NULL;
    }
    
    //Populate the new entry
    strscpy(entry->iface_name, iface_name, IFNAMSIZ);
    entry->packet_count = 0;
    entry->last_packet_time = jiffies;
    entry->vlan_id = vlan_id;

    //Add the new entry to our list
    spin_lock_irqsave(&rate_lock, flags);
    list_add(&entry->list, &rate_limit_list);
    spin_unlock_irqrestore(&rate_lock, flags);

    return entry;

}


/**
 * rate_limit_reached - Calculate if the rate limit was reached.
 * @skb: The network packet (sk_buff) that is being processed.
 *
 * This function checks whether the rate limit for a given network interface has
 * been exceeded based on a given time window. If the rate limit is exceeded,
 * it returns true, indicating the packet should be dropped. Otherwise, it 
 * returns false, allowing the packet to proceed. The function also ensures that
 * rate limit entries are created for interfaces that do not have them yet.
 *
 * Return: true if the rate limit has been exceeded and the packet should be dropped, 
 *         false if the packet can be processed.
 */
bool rate_limit_reached(const char *interface_name, u16 vlan_id){
    struct rate_limit_entry *entry;
    unsigned long current_time = jiffies;
    // Get or create a rate limit entry for the interface
    printk(KERN_INFO "kdai: Getting the current rate limit entry for %s\n", interface_name);
    entry = get_rate_limit_entry(interface_name, vlan_id);
    //If we did not already have an entry
    if (entry == NULL) {
        //Attempt to create an entry
        printk(KERN_INFO "kdai: No rate limit entry existed creating one...\n");
        entry = create_rate_limit_entry(interface_name, vlan_id);
        //If we could not create an entry
        if (entry == NULL) {
            //Drop packets by default
            printk(KERN_INFO "kdai: Could not create a rate limit entry dropping...\n");
            return true; // Rate limit reached == true
        }
    }
    //At this point we have either found or created a new rate limit entry
    printk(KERN_INFO "kdai: Current count is %d\n", entry->packet_count);

    // Check if the time window has elapsed
    //if the current time is after the earliest valid timestamp when a new packet can be processed
    //( the earliest valid timestamp when a new packet can be processes is entry->last_packet_time + msecs_to_jiffies(RATE_LIMIT_WINDOW) )
    if (time_after(current_time, entry->last_packet_time + msecs_to_jiffies(RATE_LIMIT_WINDOW))) {
        // Reset the packet_count and last_packet_received time
        printk(KERN_INFO "kdai: Time window has elapsed, reset the packet count for %s\n", interface_name);
        entry->packet_count = 0; 
        entry->last_packet_time = current_time;
    }

    // Since the rate limit has not been exceeded update the packet_count
    // Increment packet count and allow the packet
    printk(KERN_INFO "kdai: The Packet count was added to the entry\n");
    entry->packet_count++;
    printk(KERN_INFO "kdai: Current count is %d\n", entry->packet_count);

    // If the Rate limit has exceeded the MAX_PACKETS_PER_WINDOW
    if (entry->packet_count >= MAX_PACKETS_PER_WINDOW) {
        // Rate limit reached
        printk(KERN_INFO "kdai: The Rate Limit Exceeded!\n");
        return true; 
    }

    return false;
}

/**
 * clean_rate_limit_table - Free allocated memory for all rate limit entries in the list.
 *
 * This function iterates through the global list of rate limit entries, removes 
 * each entry from the list, and frees the allocated memory. 
 * The operation is done under a spinlock to ensure thread safety.
 *
 */
void clean_rate_limit_table(void){
    struct list_head* curr, *next;
    struct rate_limit_entry* entry;
    unsigned long flags;

    spin_lock_irqsave(&rate_lock, flags);
    list_for_each_safe(curr, next, &rate_limit_list) {
        entry = list_entry(curr, struct rate_limit_entry, list);
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&rate_lock, flags);
}