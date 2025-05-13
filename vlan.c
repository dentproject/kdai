#include "vlan.h"
#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include<linux/sort.h>

#define VLAN_HASH_BITS 8
#define VLAN_HASH_SIZE (1 << VLAN_HASH_BITS)

static struct hlist_head vlan_hash_table[VLAN_HASH_SIZE];
int currentNumberOfVLANs;

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

    if(vlan_should_be_inspected(vlan_id)){
        //We already have this vlan
        return;
    }

    unsigned int hash = vlan_hash(vlan_id);
    struct vlan_hash_entry *entry = kmalloc(sizeof(struct vlan_hash_entry), GFP_KERNEL);
    if (!entry)
        return;

    currentNumberOfVLANs++;
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

int compare_u16(const void * a, const void * b){
    return *(u16 *)a - *(u16 *)b;
}
// Print all VLANs currently in the hash table
void print_all_vlans_in_hash(void) {
    int i;
    int count = 0;
    struct vlan_hash_entry *entry;
    u16 vlan_ids [currentNumberOfVLANs];


    printk(KERN_INFO "kdai: ---- VLANs in Hash Table ----\n");

    for (i = 0; i < VLAN_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &vlan_hash_table[i], node) {
            //intk(KERN_INFO "kdai: VLAN ID: %u \t(Hash Index: %d)\n", entry->vlan_id, i);
            vlan_ids[count++] = entry->vlan_id;
        }
    }

    sort(vlan_ids, count, sizeof(u16), compare_u16, NULL);
    for(i=0; i < count; i++) {
        printk(KERN_INFO "kdai: VLAN ID:  %u\n", vlan_ids[i]);
    }
    printk(KERN_INFO "kdai: ---- End of VLAN List ----\n\n");
}

//Taken a string of comma seperated vlans and add those vlans to the inspection list
void parse_vlans(char * vlans) {
    char * token;
    char * str;
    char *to_free;

    if(vlans==NULL){
        return;
    }

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
            printk(KERN_INFO "Invalid VLAN_ID: %s\n", token);
        }
    }
    //Free the allocated memory
    kfree(to_free);

}