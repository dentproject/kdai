#include "common.h"

// Structure for storing trusted interface names
struct interface_entry {
    char name[IFNAMSIZ];    // Store trusted interface name
                            // IFNAMSIZ is a constant in the linux kernel
                            // that defines the maximum length of a network interface
    u16 vlan_id;            //The vlan associated with DAI
    struct list_head list;  // Point to the next item in the linked list 
};

// Function declarations
void populate_trusted_interface_list(void);

int insert_trusted_interface(const char *device_name, u16 vlan_id);

const char* find_trusted_interface(const char *interface_name, u16 vlan_id);

void print_trusted_interface_list(void);

void free_trusted_interface_list(void);
