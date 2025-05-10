#include "common.h"

struct rate_limit_entry {
    char iface_name[IFNAMSIZ];  // Store the interface name
    unsigned int packet_count;  // Count of packets received
    unsigned long last_packet_time;  // Time of the last packet received
    struct list_head list;

};

// Function declarations
bool rate_limit_reached(struct  sk_buff* skb);
void clean_rate_limit_table(void);