#include "vlan.h"
#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/slab.h>

#define VLAN_HASH_BITS 8
#define VLAN_HASH_SIZE (1 << VLAN_HASH_BITS)

static struct hlist_head vlan_hash_table[VLAN_HASH_SIZE];

// Hash function
static inline unsigned int vlan_hash(u16 vlan_id) {
    return hash_32(vlan_id, VLAN_HASH_BITS);
}

void init_vlan_hash_table(void) {
    int i;
    for (i = 0; i < VLAN_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&vlan_hash_table[i]);  // Initialize each hash table bucket
    }
}

// Add VLAN to be inspected
void add_vlan_to_inspect(u16 vlan_id) {
    unsigned int hash = vlan_hash(vlan_id);
    struct vlan_hash_entry *entry = kmalloc(sizeof(struct vlan_hash_entry), GFP_KERNEL);
    if (!entry)
        return;

    entry->vlan_id = vlan_id;
    hlist_add_head(&entry->node, &vlan_hash_table[hash]);
}

// Check if VLAN should be inspected
bool vlan_should_be_inspected(u16 vlan_id) {
    unsigned int hash = vlan_hash(vlan_id);
    struct vlan_hash_entry *entry;

    hlist_for_each_entry(entry, &vlan_hash_table[hash], node) {
        if (entry->vlan_id == vlan_id)
            return true;
    }
    return false;
}

// To remove a VLAN
void remove_vlan_from_inspect(u16 vlan_id) {
    unsigned int hash = vlan_hash(vlan_id);
    struct vlan_hash_entry *entry;

    hlist_for_each_entry(entry, &vlan_hash_table[hash], node) {
        if (entry->vlan_id == vlan_id) {
            hlist_del(&entry->node);
            kfree(entry);
            return;
        }
    }
}

// Print all VLANs currently in the hash table
void print_all_vlans_in_hash(void) {
    int i;
    struct vlan_hash_entry *entry;

    printk(KERN_INFO "kdai: ---- VLANs in Hash Table ----\n");

    for (i = 0; i < VLAN_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &vlan_hash_table[i], node) {
            printk(KERN_INFO "kdai: VLAN ID: %u \t(Hash Index: %d)\n", entry->vlan_id, i);
        }
    }

    printk(KERN_INFO "kdai: ---- End of VLAN List ----\n\n");
}