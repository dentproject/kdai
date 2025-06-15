#include "vlan.h"
#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include<linux/sort.h>

#define VLAN_HASH_BITS 8
#define VLAN_HASH_SIZE (1 << VLAN_HASH_BITS)
DEFINE_SPINLOCK(vlan_lock);


static struct hlist_head vlan_hash_table[VLAN_HASH_SIZE];
int currentNumberOfVLANs;

/**
 * vlan_hash - Compute hash index for a VLAN ID
 * @vlan_id: VLAN identifier
 *
 * Return: A hash bucket index for the given VLAN ID using hash_32().
 */
static inline unsigned int vlan_hash(u16 vlan_id) {
    return hash_32(vlan_id, VLAN_HASH_BITS);
}

/**
 * init_vlan_hash_table - Initialize VLAN hash table
 *
 * Sets up each bucket in the vlan_hash_table as an empty hlist head.
 */
void init_vlan_hash_table(void) {
    int i;
    for (i = 0; i < VLAN_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&vlan_hash_table[i]);  // Initialize each hash table bucket
    }
}

/**
 * add_vlan_to_inspect - Add a VLAN ID to the inspection hash table
 * @vlan_id: VLAN identifier to add
 *
 * This function adds a VLAN ID to the vlan_hash_table for inspection.
 * It first validates that the VLAN ID is within the valid range (1-4094).
 * If the VLAN is already present in the hash table, it does nothing.
 * Otherwise, it allocates memory for a new hash entry, initializes it, 
 * and inserts it at the head of the appropriate hash bucket. 
 * The insertion and lookup are protected by a spinlock.
 *
 */
void add_vlan_to_inspect(u16 vlan_id) {
    unsigned int hash;
    struct vlan_hash_entry *entry;
    unsigned long flags;
    
    // Check if VLAN ID is within valid range (1-4094)
    if (vlan_id < 1 || vlan_id >= 4095) {
        printk(KERN_INFO "Invalid VLAN ID: %u. Must be between 1 (Default All) and 4094.\n", vlan_id);
        return;
    }
    hash = vlan_hash(vlan_id);
    spin_lock_irqsave(&vlan_lock, flags);

    // Check if the VLAN already exists
    hlist_for_each_entry(entry, &vlan_hash_table[hash], node) {
        if (entry->vlan_id == vlan_id) {
            spin_unlock_irqrestore(&vlan_lock, flags);
            return;  // VLAN is already in the table, so no need to add it
        }
    }

    // If we reach here, the VLAN is not in the table, so add it    
    entry = kmalloc(sizeof(struct vlan_hash_entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock_irqrestore(&vlan_lock, flags);
        return; // Memory allocation failed
    }

    //Create and add new entry
    entry->vlan_id = vlan_id;
    hlist_add_head(&entry->node, &vlan_hash_table[hash]);
    currentNumberOfVLANs++;

    spin_unlock_irqrestore(&vlan_lock, flags);
}

/**
 * vlan_should_be_inspected - Check if a VLAN ID is in the inspection list.
 * @vlan_id: The VLAN ID to check.
 *
 * Return: true if the VLAN ID is present in the hash table of VLANs to be inspected
 *         false if the VLAN ID is NOT present in the hash table of VLANs to be inspected
 */
bool vlan_should_be_inspected(u16 vlan_id) {
    unsigned int hash = vlan_hash(vlan_id);
    struct vlan_hash_entry *entry;
    unsigned long flags;
    spin_lock_irqsave(&vlan_lock, flags);
    hlist_for_each_entry(entry, &vlan_hash_table[hash], node) {
        if (entry->vlan_id == vlan_id) {
            spin_unlock_irqrestore(&vlan_lock, flags);
            return true;
        }
    }
    spin_unlock_irqrestore(&vlan_lock, flags);
    return false;
}

/**
 * remove_vlan_from_inspect - Remove a VLAN ID from the inspection list.
 * @vlan_id: The VLAN ID to remove.
 *
 * Searches the VLAN hash table for the given VLAN ID and removes it if found,
 * freeing the associated memory and decrementing the count of VLANs.
 */
void remove_vlan_from_inspect(u16 vlan_id) {
    unsigned int hash = vlan_hash(vlan_id);
    struct vlan_hash_entry *entry;
    unsigned long flags;
    spin_lock_irqsave(&vlan_lock, flags);
    hlist_for_each_entry(entry, &vlan_hash_table[hash], node) {
        if (entry->vlan_id == vlan_id) {
            hlist_del(&entry->node);
            kfree(entry);
            currentNumberOfVLANs--;
            spin_unlock_irqrestore(&vlan_lock, flags);
            return;
        }
    }
    spin_unlock_irqrestore(&vlan_lock, flags);
}

/**
 * compare_u16 - Compare two u16 values for sorting.
 * @a: Pointer to the first u16 value.
 * @b: Pointer to the second u16 value.
 *
 * Return: Negative if *a < *b, zero if equal, positive if *a > *b.
 */
static int compare_u16(const void * a, const void * b){
    return *(u16 *)a - *(u16 *)b;
}

/**
 * print_all_vlans_in_hash - Print all VLAN IDs currently in the VLAN hash table.
 *
 * This function collects all VLAN IDs from the VLAN hash table into a dynamically
 * allocated array, sorts them in ascending order, and prints the list to the kernel log.
 * The function acquires a spinlock to protect the hash table during collection.
 */
void print_all_vlans_in_hash(void) {
    int i;
    struct vlan_hash_entry *entry;
    u16 *vlan_ids;  // Dynamically allocated array
    int count;
    unsigned long flags;

    spin_lock_irqsave(&vlan_lock, flags);
    count = 0;
    // Calculate the total number of VLANs first
    for (i = 0; i < VLAN_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &vlan_hash_table[i], node) {
            count++;
        }
    }

    // Allocate memory for vlan_ids dynamically
    vlan_ids = kmalloc_array(count, sizeof(u16), GFP_KERNEL);
    if (!vlan_ids) {
        spin_unlock_irqrestore(&vlan_lock, flags);
        printk(KERN_ERR "Memory allocation failed for VLAN list\n");
        return;
    }

    // Now fill the vlan_ids array with VLAN IDs
    count = 0;  // Reset count to reuse it for adding VLANs
    for (i = 0; i < VLAN_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &vlan_hash_table[i], node) {
            vlan_ids[count++] = entry->vlan_id;
        }
    }
    spin_unlock_irqrestore(&vlan_lock, flags);

    // Sort the VLAN IDs
    sort(vlan_ids, count, sizeof(u16), compare_u16, NULL);

    // Print the sorted VLAN IDs
    printk(KERN_INFO "kdai: ---- VLANs to Inspect ----\n");
    for (i = 0; i < count; i++) {
        printk(KERN_INFO " - VLAN ID:\t%u\n", vlan_ids[i]);
    }
    printk(KERN_INFO "kdai: ---- End of VLAN List ----\n\n");

    // Free the dynamically allocated memory
    kfree(vlan_ids);
}

/**
 * parse_vlans - Parse a comma-separated list of VLAN IDs and add them to the inspection list.
 * @vlans: A string containing comma-separated VLAN IDs (e.g., "100,200,300").
 *
 * This function duplicates the input string to safely modify it, then splits it by commas
 * to extract individual VLAN ID tokens. Each token is converted to a 16-bit unsigned integer.
 * If conversion succeeds, the VLAN ID is added to the inspection list via add_vlan_to_inspect().
 * Invalid VLAN IDs are logged as informational messages.
 *
 */
void parse_vlans(char * vlans) {
    char * token;
    char * str;
    char *to_free;

    //Duplicate the string to safely modify it
    to_free = kstrdup(vlans,GFP_KERNEL);
    str = to_free;

    //Split the vlan string into parts 
    //Ex. 100,200,300 -> 100'\0'200'\0'300'\0'
    while( (token = strsep(&str, ",")) != NULL) {
        //Token will return the start of the string
        u16 vlan_id;

        //Conver the token into an unsigned 16 bit integer
        if(kstrtou16(token, 10, &vlan_id) == 0){

            //After converting add the vlan to the inpsection list
            add_vlan_to_inspect(vlan_id); 
        } else {
            printk(KERN_INFO "Invalid VLAN_ID: \"%s\"\n", token);
        }
    }
    //Free the allocated memory
    kfree(to_free);

}

/**
 * free_all_vlan_entries - Free all entries in the VLAN hash table.
 *
 * This function iterates over all buckets in the VLAN hash table,
 * safely removes each VLAN entry from the hash lists, and frees
 * the associated memory. It also resets the global count of VLANs
 * to zero. The function acquires the vlan_lock spinlock to protect
 * concurrent access during modification of the hash table.
 *
 */
void free_all_vlan_entries(void) {
    //loop counter for hashtable buckets
    int i;
    //Pointer to VLAN hash entry for traversal
    struct vlan_hash_entry *entry;
    //Temporary pointer used for safe iteraiton
    struct hlist_node *tmp;
    unsigned long flags;

    spin_lock_irqsave(&vlan_lock, flags);
    //Loop through each bucked in the VLAN hash table
    for(i = 0; i < VLAN_HASH_SIZE; i++) {
        //Get the pointer to the current hash bucket
        struct hlist_head * head = &vlan_hash_table[i];
        //Safely iterate through each entry in the current hash bucket
        hlist_for_each_entry_safe(entry, tmp, head, node) {
            //Unlink the entry form the haslist
            hlist_del(&entry->node);
            //ree the memory allocated for this entry
            kfree(entry);
        }
    }
    // Reset the global counter tracking number of VLANs
    currentNumberOfVLANs = 0;  
    spin_unlock_irqrestore(&vlan_lock, flags);
}