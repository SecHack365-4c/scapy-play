import scapy.all as scapy

# import argparse
from scapy.all import ARP
from manuf import manuf
import nmap

# def get_arguments():
#     parser = argparse.ArgumentParser()
#     parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range")
#     options = parser.parse_args()
#     return options


def scan(ip):
    arp_request = ARP(pdst=ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=10, verbose=True)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def get_vendor_info(mac_address):
    p = manuf.MacParser()
    vendor = p.get_manuf(mac_address)
    if vendor is None:
        return "unknown"
    return vendor


def get_os_info(mac_address):
    return "unknown"


def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("----------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


# options = get_arguments()
# print(options.target)
# scan_result = scan("192.168.11.0/24")
scan_result = scan("131.206.239.0/24")
if scan_result:
    i = 0
    for mac_address in scan_result:
        i += 1
        print("deveice" + str(i) + ":")
        print("ip: " + mac_address["ip"])
        print("mac: " + mac_address["mac"])
        vender_info = get_vendor_info(mac_address["mac"])
        os_info = get_os_info(mac_address["mac"])
        print("ベンダー: " + vender_info)
        print("OS: " + os_info + "\t")
        print("")

else:
    print("ネットワーク上にデバイスは検出されませんでした。")
# print_result(scan_result)
