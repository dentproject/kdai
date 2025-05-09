#include "rate_limit.h"


#define RATE_LIMIT_WINDOW 1000  // in milliseconds (1000 = 1 second)
#define MAX_PACKETS_PER_WINDOW 15  // maximum packets per window. By default, the rate for untrusted interfaces is 15 packets per second (pps)
#define MAX_INTERFACES 128  // maximum number of interfaces (you can adjust this)

static struct rate_limit_entry *rate_limit_table[MAX_INTERFACES];

struct rate_limit_entry {
    char iface_name[IFNAMSIZ];  // Store the interface name
    unsigned int packet_count;  // Count of packets received
    unsigned long last_packet_time;  // Time of the last packet received
};

// Create a new rate limit entry or return NULL if allocation fails
struct rate_limit_entry* create_rate_limit_entry(const char *iface_name) {
    int index;

    // Check if the entry for the given interface already exists
    for (index = 0; index < MAX_INTERFACES; index++) {
        if (rate_limit_table[index] && strcmp(rate_limit_table[index]->iface_name, iface_name) == 0) {
            return NULL;  // Entry already exists, return NULL (or you could reset the entry instead)
        }
    }

    // Find an empty spot in the rate limit table
    for (index = 0; index < MAX_INTERFACES; index++) {
        if (!rate_limit_table[index]) {
            break;  // Found an empty slot
        }
    }

    if (index == MAX_INTERFACES) {
        return NULL;  // No available space in the table
    }

    // Allocate memory for a new entry
    rate_limit_table[index] = kmalloc(sizeof(struct rate_limit_entry), GFP_KERNEL);
    if (!rate_limit_table[index]) {
        return NULL;  // Memory allocation failed
    }

    // Initialize the rate limit entry
    strncpy(rate_limit_table[index]->iface_name, iface_name, IFNAMSIZ);
    rate_limit_table[index]->packet_count = 0;
    rate_limit_table[index]->last_packet_time = 0;

    return rate_limit_table[index];  // Return the created entry
}

// Get an existing rate limit entry by interface name
struct rate_limit_entry* get_rate_limit_entry(const char *iface_name) {
    int index;

    // Search the rate limit table for the entry matching the interface name
    for (index = 0; index < MAX_INTERFACES; index++) {
        if (rate_limit_table[index] && strcmp(rate_limit_table[index]->iface_name, iface_name) == 0) {
            return rate_limit_table[index];  // Return the found entry
        }
    }

    return NULL;  // No entry found for the given interface name
}

//Calcualte if the rate limit was reached. Return true or false.
bool rate_limit_reached(struct sk_buff* skb){
    struct net_device *dev = skb->dev;
    struct rate_limit_entry *entry;
    unsigned long current_time = jiffies;

    // Get or create a rate limit entry for the interface
    printk(KERN_INFO "kdai: Getting the current rate limit entry for %s\n", dev->name);
    entry = get_rate_limit_entry(dev->name);
    if (!entry) {
        printk(KERN_INFO "kdai: No rate limit entry existed creating one...\n");
        entry = create_rate_limit_entry(dev->name);
        if (!entry) {
            printk(KERN_INFO "kdai: Could not create a rate limit entry dropping...\n");
            return true; // If creation fails, drop packets by default
        }
    }
    printk(KERN_INFO "kdai: Current count is %d\n", entry->packet_count);

    // Check if the time window has elapsed
    //if the current time is after the earliest valid timestamp when a new packet can be processes
    //the earliest valid timestamp when a new packet can be processes is entry->last_packet_time + msecs_to_jiffies(RATE_LIMIT_WINDOW)
    if (time_after(current_time, entry->last_packet_time + msecs_to_jiffies(RATE_LIMIT_WINDOW))) {
        // Reset the packet_count and last_packet_recieved time
        printk(KERN_INFO "kdai: Time window has elapsed, reset the packet count for %s\n", dev->name);
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

//Free allocated memmory
void clean_rate_limit_table(void){
    int index;
    //Iteratre through the rate limit table
    for (index = 0; index < MAX_INTERFACES; index++){
        //If the rate_limit_entry exists tthere was an allocated entry
        if(rate_limit_table[index]){
            //Free the allocated mmory for the entry
            kfree(rate_limit_table[index]);
            //Set the pointer to null 
            rate_limit_table[index] = NULL;
        }
    }
}