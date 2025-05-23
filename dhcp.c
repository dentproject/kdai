#include "dhcp.h"
#include "errno.h"

LIST_HEAD(dhcp_snooping_list);

DEFINE_SPINLOCK(slock);

struct task_struct* dhcp_thread = NULL;

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

//Continuously check the list of DHCP snooping entries and remove any entries that ave expired based on their
//expiration time
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
