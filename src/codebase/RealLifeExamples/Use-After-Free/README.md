https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=double+free

There are 7778 CVE Records that match "Double Free"


https://cwe.mitre.org/data/definitions/416.html
About CWE
Common Weakness Enumeration (CWE™) is a community-developed list of common software and hardware weaknesses. 
A “weakness” is a condition in a software, firmware, hardware, or service component that, under certain circumstances, could contribute to the introduction of vulnerabilities. 
The CWE List and associated classification taxonomy identify and describe weaknesses in terms of CWEs.

Knowing the weaknesses that result in vulnerabilities means software developers, hardware designers, and security architects can eliminate them before deployment, when it is much easier and cheaper to do so.


CVE-2022-20141 Description:
In ip_check_mc_rcu of igmp.c, there is a possible use after free due to improper locking. 
This could lead to local escalation of privilege when opening and closing inet sockets with no additional execution privileges needed. 
User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-112551163References: Upstream kernel


CVE-2022-2621 Description:
Chain: two threads in a web browser use the same resource (CWE-366), but one of those threads can destroy the resource before the other has completed (CWE-416).


CVE-2021-0920 Description:
In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References: Upstream kernel


CVE-2010-4168 Description:
Multiple use-after-free vulnerabilities in OpenTTD 1.0.x before 1.0.5 allow (1) remote attackers to cause a denial of service (invalid write and daemon crash) by abruptly disconnecting during transmission of the map from the server, related to network/network_server.cpp; (2) remote attackers to cause a denial of service (invalid read and daemon crash) by abruptly disconnecting, related to network/network_server.cpp; and (3) remote servers to cause a denial of service (invalid read and application crash) by forcing a disconnection during the join process, related to network/network.cpp.


CVE-2010-2941 Descirption
ipp.c in cupsd in CUPS 1.4.4 and earlier does not properly allocate memory for attribute values with invalid string data types, which allows remote attackers to cause a denial of service (use-after-free and application crash) or possibly execute arbitrary code via a crafted IPP request.
