#include "common.h"

struct vlan_hash_entry {
    u16 vlan_id;
    struct hlist_node node;
};

void add_vlan_to_inspect(u16 vlan_id);

bool vlan_should_be_inspected(u16 vlan_id);

void remove_vlan_from_inspect(u16 vlan_id);

void print_all_vlans_in_hash(void);

void init_vlan_hash_table(void);

void parse_vlans(char * vlans);