https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=buffer+overflow

There are 16292 CVE Records that match "Buffer Overflow"

https://cwe.mitre.org/data/definitions/121.html Stack-based Buffer Overflow

https://cwe.mitre.org/data/definitions/122.html Heap-based Buffer Overflow


About CWE Common Weakness Enumeration (CWE™) is a community-developed list of common software and hardware weaknesses. A “weakness” is a condition in a software, firmware, hardware, or service component that, under certain circumstances, could contribute to the introduction of vulnerabilities. The CWE List and associated classification taxonomy identify and describe weaknesses in terms of CWEs.

Knowing the weaknesses that result in vulnerabilities means software developers, hardware designers, and security architects can eliminate them before deployment, when it is much easier and cheaper to do so.

CVE-2024-9915 Definition:
A vulnerability classified as critical was found in D-Link DIR-619L B1 2.06. Affected by this vulnerability is the function formVirtualServ of the file /goform/formVirtualServ. The manipulation of the argument curTime leads to buffer overflow. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

CVE-2024-5197 Definition:
There exists interger overflows in libvpx in versions prior to 1.14.1. Calling vpx_img_alloc() with a large value of the d_w, d_h, or align parameter may result in integer overflows in the calculations of buffer sizes and offsets and some fields of the returned vpx_image_t struct may be invalid. Calling vpx_img_wrap() with a large value of the d_w, d_h, or stride_align parameter may result in integer overflows in the calculations of buffer sizes and offsets and some fields of the returned vpx_image_t struct may be invalid. We recommend upgrading to version 1.14.1 or beyond

CVE-2024-49895 Definition:
In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Fix index out of bounds in DCN30 degamma hardware format translation This commit addresses a potential index out of bounds issue in the `cm3_helper_translate_curve_to_degamma_hw_format` function in the DCN30 color management module. The issue could occur when the index 'i' exceeds the number of transfer function points (TRANSFER_FUNC_POINTS). The fix adds a check to ensure 'i' is within bounds before accessing the transfer function points. If 'i' is out of bounds, the function returns false to indicate an error. Reported by smatch: drivers/gpu/drm/amd/amdgpu/../display/dc/dcn30/dcn30_cm_common.c:338 cm3_helper_translate_curve_to_degamma_hw_format() error: buffer overflow 'output_tf->tf_pts.red' 1025 <= s32max drivers/gpu/drm/amd/amdgpu/../display/dc/dcn30/dcn30_cm_common.c:339 cm3_helper_translate_curve_to_degamma_hw_format() error: buffer overflow 'output_tf->tf_pts.green' 1025 <= s32max drivers/gpu/drm/amd/amdgpu/../display/dc/dcn30/dcn30_cm_common.c:340 cm3_helper_translate_curve_to_degamma_hw_format() error: buffer overflow 'output_tf->tf_pts.blue' 1025 <= s32max

CVE-2024-49777 Definition:
A heap-based buffer overflow in tsMuxer version nightly-2024-03-14-01-51-12 allows attackers to cause Denial of Service (DoS), Information Disclosure and Code Execution via a crafted MKV video file.

CVE-2024-42546 Definition:
TOTOLINK A3100R V4.1.2cu.5050_B20200504 has a buffer overflow vulnerability in the password parameter in the loginauth function.
