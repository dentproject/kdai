#include "trusted_interfaces.h"
#include "errno.h"

LIST_HEAD(trusted_interface_list);  // Global list head for interfaces
DEFINE_SPINLOCK(interface_lock);
static int trusted_list_size = 0;

/**
 * populate_trusted_interface_list - Populate the trusted interface list with all network interfaces
 *
 * This function iterates over all network interfaces in the system and inserts each one into 
 * the trusted interface list.
 */
void populate_trusted_interface_list(void) {
    struct net_device *dev;
    // Iterate over all network interfaces
    for_each_netdev(&init_net, dev) {
        insert_trusted_interface(dev->name, 0);
    }
}

/**
 * insert_trusted_interface - Insert a new interface into the trusted list.
 * @device_name: The name of the trusted interface to insert
 * @vlan_id: The vlan associated for DAI
 * 
 * This fucntion inserts the name of a network interface into teh trusted interface list. 
 * It first checks if the interface already exists in the list using find_trusted_interface. 
 * If the interface is not found it alloactes memory for a new entry, and cpoies the device name. 
 * The list field is the intialized for the new entry and this fucntion adds the new entry to
 * the end fo the lis tusing list_add_tail. The trusted_list_size if then incremented, and 
 * a message is printed to indicate the enw addition.asm
 * 
 * Return: 1 if the interface name was added,
 *         0 if it already exists,
 *        -1 if memory allocation failed,
 *        -2 if the interface was not found,
 *        -3 if the VLAN ID was invalid.
 */
int insert_trusted_interface(const char *device_name, u16 vlan_id) {
    struct net_device *dev;
    struct interface_entry *new_entry;
    unsigned long flags;

    //If we found that device already return
    if(find_trusted_interface(device_name, vlan_id)){
        return 0;
    }

    // Check if the interface exists
    dev = dev_get_by_name(&init_net, device_name);
    if (!dev) {
        printk(KERN_INFO "Interface not found: \"%s\"\n", device_name);
        return -2;
    }

    // Release Interface after use
    dev_put(dev);

    // Check if VLAN ID is within valid range (1-4094)
    if (vlan_id < 1 || vlan_id >= 4095) {
        printk(KERN_INFO "Invalid VLAN ID: %u. Must be between 1 (Default All) and 4094.\n", vlan_id);
        return -3;
    }

    // Allocate memory for the new entry
    new_entry = kmalloc(sizeof(struct interface_entry), GFP_KERNEL);
    if (!new_entry) {
        printk(KERN_ERR "Failed to allocate memory for interface entry\n");
        return -1;
    }

    // Copy the device name safely
    strncpy(new_entry->name, device_name, IFNAMSIZ - 1);
    new_entry->name[IFNAMSIZ - 1] = '\0'; // Ensure null termination
    new_entry->vlan_id = vlan_id;

    // Initialize the list field of the new entry
    INIT_LIST_HEAD(&new_entry->list);
    // Add to the end of the list
    spin_lock_irqsave(&interface_lock, flags);
    list_add_tail(&new_entry->list, &trusted_interface_list);
    trusted_list_size++;
    spin_unlock_irqrestore(&interface_lock, flags);
    

    //printk(KERN_INFO "Added interface: %s\n", new_entry->name);

    return 1;
}

/**
 * find_trusted_interface - Find an interface in the trusted list.
 * @interface_name: The name of the interface to find.
 * @vlan_id: The VLAN ID associated with the interface.
 *
 * This function searches the trusted interface list for an entry that matches
 * the given interface name and VLAN ID. If a matching entry is found, the function
 * returns the name of the interface. If no match is found, it returns NULL.
 *
 * Return: The name of the trusted interface if found, or NULL if not found.
 */
const char* find_trusted_interface(const char *interface_name, u16 vlan_id) {
    struct interface_entry *entry;
    unsigned long flags;
    spin_lock_irqsave(&interface_lock, flags);
    // Loop through the list to find a matching interface name
    list_for_each_entry(entry, &trusted_interface_list, list) {
        if (strncmp(entry->name, interface_name, IFNAMSIZ) == 0 && entry->vlan_id == vlan_id) {
            spin_unlock_irqrestore(&interface_lock, flags);
            return entry->name; // Interface found, return interface
        }
    }
    spin_unlock_irqrestore(&interface_lock, flags);

    return NULL; // Interface not found, return NULL
}

/**
 * print_trusted_interface_list - Print all interfaces in the trusted list.
 *
 * This function logs the names and VLAN IDs of all network interfaces currently
 * stored in the trusted interface list. If the list is empty, it prints a message
 * indicating that no interfaces are trusted and all are treated as untrusted.
 *
 */
void print_trusted_interface_list(void) {
    struct interface_entry *entry;
    unsigned long flags;

    printk(KERN_INFO "kdai: ---- Trusted Network Interfaces List ---\n");

    //If the list is empty notify the user
    if(trusted_list_size == 0) {
        printk(KERN_INFO "kdai: The list is currently empty!\n");
        printk(KERN_INFO "kdai: All interfaces are Untrusted.\n");
        printk(KERN_INFO "kdai: ---- Trusted Network Interfaces List ---\n\n");
        return;
    }
        
    spin_lock_irqsave(&interface_lock, flags);
    //Iterate and print each entry
    list_for_each_entry(entry, &trusted_interface_list, list) {
        printk(KERN_INFO " - VLAN ID:\t%u \t\t Interface:\t%s\n",  entry->vlan_id, entry->name);
    }
    spin_unlock_irqrestore(&interface_lock, flags);
    
    printk(KERN_INFO "kdai: ---- End of Trusted Network Interfaces List ---\n\n");

}

/**
 * free_trusted_interface_list - Free all entries in the trusted interface list.
 *
 * This function iterates through the trusted interface list and frees each entry.
 * It uses list_for_each_entry_safe to safely traverse the list while deleting entries.
 * This allows safe deletion by storing the next pointer before removing the current one.
 * Each entry is removed using list_del and its memory is freed with kfree.
 *
 */
void free_trusted_interface_list(void) {
    struct interface_entry *entry, *tmp;
    unsigned long flags;
    spin_lock_irqsave(&interface_lock, flags);
    //Iterate through the list, del and free each entry.
    list_for_each_entry_safe(entry, tmp, &trusted_interface_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    trusted_list_size = 0;
    spin_unlock_irqrestore(&interface_lock, flags);
}


/**
 * parse_interfaces_and_vlan - parse a comma-separated list of interfaces with VLANs and add them to the trusted list
 * @interfaces_and_vlan: string of comma-separated interface:vlan pairs, e.g. "eth0:1,eth1:2"
 *
 * Parses the string containing interface and VLAN pairs separated by commas.
 * Each pair is separated by ':' into interface name and VLAN ID.
 * Calls insert_trusted_interface() to add each valid pair to the trusted list.
 * Invalid entries (missing colon or invalid VLAN) are ignored with an info message.
 *
*/
void parse_interfaces_and_vlan(char * interfaces_and_vlan) {
    char * token;
    char * vlan_id_str;
    char * str;
    char *to_free;
    u16 vlan_id;

    //Duplicate the string to safely modify it
    to_free = kstrdup(interfaces_and_vlan,GFP_KERNEL);
    str = to_free;

    //Split the interfaces_and_vlan string into parts 
    //Ex. enp0s1:100,enp0s2:200,enp0s3:300 -> enp0s1:100'\0'enp0s2:200'\0'enp0s3:300'\0'
    while( (token = strsep(&str, ",")) != NULL) {
        //Token will return the start of the string
        //Ex. enp0s1:100

        //Find the deliminator and null terminate the interface from the vlan;
        vlan_id_str = strstr(token, ":");
        if (!vlan_id_str) {
            printk(KERN_INFO "Invalid Format (Expected: eth0:1), Input Recieved: \"%s\"\n", interfaces_and_vlan);
            continue;
        }
        *vlan_id_str='\0';
        //Move to the start of the vlan_id
        vlan_id_str++;

        //Convert the token into an unsigned 16 bit integer
        if(kstrtou16(vlan_id_str, 10, &vlan_id) == 0){
            //After converting add the interface and vlan to the trusted list
            insert_trusted_interface(token, vlan_id);
        } else {
            printk(KERN_INFO "Input Format Error for Trusted Interface (Expected: eth0:1)\n");
        }
    }
    //Free the allocated memory
    kfree(to_free);

}