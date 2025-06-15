#ifndef MODULE_PARAMS_H
#define MODULE_PARAMS_H

#include "common.h"

// Module parameter variables
extern bool globally_enabled_DAI;  // Enable DAI inspection for all packets under a single VLAN
extern bool static_ACL_Enabled;    // DAI inspection uses static ACLs only
extern char *vlans_to_inspect;     // Comma-separated VLAN list for DAI inspection
extern char *trusted_interfaces;   // Comma-separated trusted Interface:VLAN_ID pairs

#endif