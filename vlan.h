#include "common.h"

struct vlan_hash_entry {
    unsigned int vlan_id;
    struct hlist_node node;
};

void add_vlan_to_inspect(unsigned int vlan_id);

bool vlan_should_be_inspected(unsigned int vlan_id);

void remove_vlan_from_inspect(unsigned int vlan_id);