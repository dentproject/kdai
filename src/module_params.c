#include "dhcp.h"
#include "trusted_interfaces.h"
#include "rate_limit.h"
#include "vlan.h"
#include "errno.h"
#include "module_params.h"

//The following are the avilable Kernel Module Parameters

bool globally_enabled_DAI = false;  //Default is false; When true Enable DAI inspection for all packets under a single VLAN
bool static_ACL_Enabled = false;    //Default is false; When true DAI inspection uses static ACLs only, DHCP snooping is nNOT considered
char * vlans_to_inspect = NULL;     //Default is None; Comma-separated list of VLANs for DAI inspection
char * trusted_interfaces = NULL;   //Default is None; Comma-separated list of trusted Interfaces:VLAN_ID pairs

/**
 * set_globally_enabled_DAI - Set global DAI inspection enable flag
 * @val: Input string representing a boolean value ("0", "1", "true", or "false")
 * @kp: Pointer to the kernel_param structure (unused)
 *
 * Updates the global flag globally_enabled_DAI based on the input value.
 * This flag enables or disables DAI inspection for all packets, assuming
 * all packets belong to the same VLAN.
 *
 * If the input is invalid, logs an error and returns a negative error code.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int set_globally_enabled_DAI(const char *val, const struct kernel_param *kp)
{
    bool tmp;
    // Convert the input string (e.g., "1" or "true") to a boolean (0 or 1)
    int ret = kstrtobool(val, &tmp);
    if (ret < 0) {
        printk(KERN_INFO "kdai: globally_enabled_DAI was NOT updated, input was invalid\n\n");
        return ret;
    }

    // Log the old value before updating and the new value after
    printk(KERN_INFO "kdai: globally_enabled_DAI updated from %d to %d\n\n", globally_enabled_DAI, tmp);
    
    globally_enabled_DAI = tmp;

    return 0;
}
static const struct kernel_param_ops globally_enabled_DAI_ops = {
    .set = set_globally_enabled_DAI, //This funciton will be called whenever the static_ACL_Enabled variable is written too
    .get = param_get_bool, //This function will be called whenever the static_ACL_Enabled variable is read
};
module_param_cb(globally_enabled_DAI, &globally_enabled_DAI_ops, &globally_enabled_DAI, 0644);
MODULE_PARM_DESC(globally_enabled_DAI, "Enable or disable DAI Inspection for all Packets. All packets will be assumed to be in the same VLAN.");

/**
 * set_static_acl - Set the static ACL inspection mode
 * @val: Input string representing a boolean value ("0", "1", "true", or "false")
 * @kp: Pointer to the kernel_param structure (unused)
 *
 * Updates the global static_ACL_Enabled flag based on the input value.
 * If the input is invalid (i.e., not a valid boolean), the function logs
 * an error and returns an appropriate error code.
 *
 * This controls whether DAI (Dynamic ARP Inspection) falls back to static
 * ACLs for packets not found in the ARP table.
 *
 * Return: 0 on success, negative error code on failure (e.g. -EINVAL).
 */
static int set_static_acl(const char *val, const struct kernel_param *kp)
{
    bool tmp;
    // Convert the input string (e.g., "1" or "true") to a boolean (0 or 1)
    int ret = kstrtobool(val, &tmp);
    if (ret < 0) {
        printk(KERN_INFO "kdai: static_ACL_Enabled was NOT updated, input was invalid\n\n");
        return ret;
    }

    // Log a message to the kernel log to confirm the update
    printk(KERN_INFO "kdai: static_ACL_Enabled updated from %d to %d\n\n", static_ACL_Enabled, tmp);

    static_ACL_Enabled = tmp;
    return 0;
}
static const struct kernel_param_ops static_acl_ops = {
    .set = set_static_acl, //This funciton will be called whenever the static_ACL_Enabled variable is written too
    .get = param_get_bool, //This function will be called whenever the static_ACL_Enabled variable is read
};
module_param_cb(static_ACL_Enabled, &static_acl_ops, &static_ACL_Enabled, 0644);
MODULE_PARM_DESC(static_ACL_Enabled, "Enable or disable DAI Inspection using static ACLs ONLY. Static Entries for packets not found in the ARP table will be dropped.");

/**
 * set_vlans_to_inspect - Set the VLANs to inspect via module parameter
 * @val: Input string with comma-separated VLAN IDs or special "clear" string
 * @kp: Pointer to kernel_param structure (unused)
 *
 * Called when the `vlans_to_inspect` module parameter is written. Accepts a
 * comma-separated list of VLAN IDs (e.g., "100,200,300") or the special string
 * "clear", which removes all entries from the inspection list.
 *
 * On valid input, clears the current list and adds the new VLANs by calling
 * parse_vlans(). Memory allocation is performed for parsing, and a failure to
 * allocate memory will prevent changes.
 *
 * Return: 0 on success, -ENOMEM if memory allocation fails.
 */
static int set_vlans_to_inspect(const char *val, const struct kernel_param *kp){
    char *to_free; // Declare to_free for duplicating the string
    char *str;
    
    // If the input string is empty, just return
    if (val == NULL) {
        printk(KERN_INFO "kdai: No VLANs to inspect (empty input).\n\n");
        return 0;
    }
    if (strcmp(val,"clear") == 0) {
        printk(KERN_INFO "kdai: Clearing VLANs To Inspect list\n\n");
        free_all_vlan_entries();
        print_all_vlans_in_hash();
        return 0;
    }

    // Parse the incoming string of VLANs
    to_free = kstrdup(val, GFP_KERNEL);
    if (!to_free) {
        printk(KERN_INFO "kdai: Could not dup\n\n");
        return -ENOMEM; // Memory allocation failed
    }
    str = to_free;

    //Remove all VLAN_ID entries from the list
    printk(KERN_INFO "kdai: Clearing VLANs To Inspect list\n\n");
    free_all_vlan_entries();

    //Add all entries that are specified in new val
    printk(KERN_INFO "kdai: Parsing VLANs To Inspect\n\n");
    parse_vlans(to_free);

    //Free allocate dmmemory
    kfree(to_free);

    printk(KERN_INFO "kdai: VLANs to inspect updated.\n\n");
    print_all_vlans_in_hash();
    return 0;
}
static const struct kernel_param_ops vlans_to_inspect_ops = {
    .set = set_vlans_to_inspect, //This funciton will be called whenever the static_ACL_Enabled variable is written too
    .get = param_get_charp, //This function will be called whenever the static_ACL_Enabled variable is read
};
module_param_cb(vlans_to_inspect, &vlans_to_inspect_ops, &vlans_to_inspect, 0644);
MODULE_PARM_DESC(vlans_to_inspect, "Comma-separated list of VLANs DAI should inspect");

/**
 * set_trusted_interfaces - Update the list of trusted interfaces from a module parameter
 * @val: Input string containing comma-separated interface:VLAN_ID pairs
 * @kp: Pointer to kernel_param structure (unused)
 *
 * This function is called when the `trusted_interfaces` module parameter is written.
 * It parses a comma-separated string of interface:VLAN_ID entries, such as:
 * "eth0:10,eth1:20", and updates the trusted interface list accordingly.
 *
 * If the special string "clear" is passed, the trusted list is cleared.
 * If the string is NULL or empty, the function exits with no changes.
 *
 * Return: 0 on success, -ENOMEM if memory allocation fails.
 */
static int set_trusted_interfaces(const char *val, const struct kernel_param *kp){
    char *to_free; // Declare to_free for duplicating the string
    char *str;
    
    printk(KERN_INFO "kdai: Changed Trusted Interface List\n");
    // If the input string is empty, just return
    if (val == NULL) {
        printk(KERN_INFO "kdai: Empty input for Trusted Interfaces.\n\n");
        return 0;
    }
    if(strcmp(val,"clear") == 0) {
        printk(KERN_INFO "kdai: Clearing Trusted list\n\n");
        free_trusted_interface_list();
        print_trusted_interface_list();
        return 0;
    }

    // Parse the incoming string of VLANs
    to_free = kstrdup(val, GFP_KERNEL);
    if (!to_free) {
        printk(KERN_INFO "kdai: Could not dup\n\n");
        return -ENOMEM; // Memory allocation failed
    }
    str = to_free;

    //Remove all trusted entries from the list
    free_trusted_interface_list();

    //Add all entries that are specified in new val
    parse_interfaces_and_vlan(to_free);

    //Free allocate dmmemory
    kfree(to_free);

    printk(KERN_INFO "kdai: Trusted Interfaces Updated.\n\n");
    print_trusted_interface_list();
    return 0;
}
static const struct kernel_param_ops trusted_interfaces_ops = {
    .set = set_trusted_interfaces, //This funciton will be called whenever the static_ACL_Enabled variable is written too
    .get = param_get_charp, //This function will be called whenever the static_ACL_Enabled variable is read
};
module_param_cb(trusted_interfaces, &trusted_interfaces_ops, &trusted_interfaces, 0644);
MODULE_PARM_DESC(trusted_interfaces, "Comma-separated list of Interfaces:VLAN_ID that are considered to be trusted");