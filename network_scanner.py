#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    """
    يقوم بمسح الشبكة للبحث عن الأجهزة باستخدام عنوان IP أو نطاق IP المحدد.
    Sends an ARP request to the specified IP or IP range and returns a list of clients that responded.
    """
    # 1. إنشاء طلب ARP
    # pdst = destination IP address
    arp_request = scapy.ARP(pdst=ip)

    # 2. إنشاء إطار إيثرنت
    # dst = destination MAC address. "ff:ff:ff:ff:ff:ff" is the broadcast MAC address.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # 3. دمج الطلبين معاً
    arp_request_broadcast = broadcast/arp_request

    # 4. إرسال الحزمة واستقبال الردود
    # srp = send and receive packet. Returns two lists: answered and unanswered.
    # timeout=1 means it will wait 1 second for a response.
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # 5. تحليل الردود
    clients_list = []
    for element in answered_list:
        # element[1] contains the ARP response. psrc is the sender's IP, hwsrc is the sender's MAC.
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    """
    يطبع النتائج بتنسيق جدول.
    Prints the list of clients in a formatted table.
    """
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# --- التنفيذ الرئيسي ---
# لتسهيل الاختبار، سنقوم بمسح نطاق شبكة شائع.
# يمكن للمستخدم تغيير هذا النطاق ليتناسب مع شبكته.
# ملاحظة: يجب تشغيل هذا السكربت بصلاحيات المدير (root/administrator) ليعمل بشكل صحيح.
target_ip = "192.168.1.1/24"
print(f"[*] Scanning network: {target_ip}")
scan_result = scan(target_ip)

if scan_result:
    print_result(scan_result)
else:
    print("[-] No devices found on the network.")
