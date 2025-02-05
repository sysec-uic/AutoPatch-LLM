https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=double+free

There are 676 CVE Records that match "Double Free"

(https://cwe.mitre.org/data/definitions/415.html) About CWE Common Weakness Enumeration (CWE™) is a community-developed list of common software and hardware weaknesses. A “weakness” is a condition in a software, firmware, hardware, or service component that, under certain circumstances, could contribute to the introduction of vulnerabilities. The CWE List and associated classification taxonomy identify and describe weaknesses in terms of CWEs.

Knowing the weaknesses that result in vulnerabilities means software developers, hardware designers, and security architects can eliminate them before deployment, when it is much easier and cheaper to do so.


CVE-2024-50235 Definition: 
In the Linux kernel, the following vulnerability has been resolved: wifi: cfg80211: clear wdev->cqm_config pointer on free When we free wdev->cqm_config when unregistering, we also need to clear out the pointer since the same wdev/netdev may get re-registered in another network namespace, then destroyed later, running this code again, which results in a double-free.

CVE-2024-50215 Definition:
In the Linux kernel, the following vulnerability has been resolved: nvmet-auth: assign dh_key to NULL after kfree_sensitive ctrl->dh_key might be used across multiple calls to nvmet_setup_dhgroup() for the same controller. So it's better to nullify it after release on error path in order to avoid double free later in nvmet_destroy_auth(). Found by Linux Verification Center (linuxtesting.org) with Svace.

CVE-2024-50159 Definition:
In the Linux kernel, the following vulnerability has been resolved: firmware: arm_scmi: Fix the double free in scmi_debugfs_common_setup() Clang static checker(scan-build) throws below warning&#65306; | drivers/firmware/arm_scmi/driver.c:line 2915, column 2 | Attempt to free released memory. When devm_add_action_or_reset() fails, scmi_debugfs_common_cleanup() will run twice which causes double free of 'dbg->name'. Remove the redundant scmi_debugfs_common_cleanup() to fix this problem.

CVE-2024-50152 Definition:
In the Linux kernel, the following vulnerability has been resolved: smb: client: fix possible double free in smb2_set_ea() Clang static checker(scan-build) warning&#65306; fs/smb/client/smb2ops.c:1304:2: Attempt to free released memory. 1304 | kfree(ea); | ^~~~~~~~~ There is a double free in such case: 'ea is initialized to NULL' -> 'first successful memory allocation for ea' -> 'something failed, goto sea_exit' -> 'first memory release for ea' -> 'goto replay_again' -> 'second goto sea_exit before allocate memory for ea' -> 'second memory release for ea resulted in double free'. Re-initialie 'ea' to NULL near to the replay_again label, it can fix this double free problem.

CVE-2024-50071 Definition:
In the Linux kernel, the following vulnerability has been resolved: pinctrl: nuvoton: fix a double free in ma35_pinctrl_dt_node_to_map_func() 'new_map' is allocated using devm_* which takes care of freeing the allocated data on device removal, call to .dt_free_map = pinconf_generic_dt_free_map double frees the map as pinconf_generic_dt_free_map() calls pinctrl_utils_free_map(). Fix this by using kcalloc() instead of auto-managed devm_kcalloc().
