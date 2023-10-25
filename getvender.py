import scapy.all as scapy
from fingerprint import fingerprint


def get_mac_addresses(network):
    """
    ネットワーク上のすべての機器のMacアドレスを取得する

    Args:
      network: スキャンするネットワークのIPアドレス

    Returns:
      スキャンされた機器のMacアドレスのリスト
    """

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = scapy.ARP(pdst=network)
    arp_response = scapy.ARP()

    packets = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)

    mac_addresses = []
    for packet in packets:
        if isinstance(packet, scapy.ARP):
            mac_addresses.append(packet.hwsrc)

    return mac_addresses


def get_device_info(mac_address):
    """
    Macアドレスから端末のベンダー情報とos情報を取得する

    Args:
      mac_address: 取得する端末のMacアドレス

    Returns:
      端末のベンダー情報とos情報の辞書
    """

    device_info = {}
    vendor_info = fingerprint.get_vendor(mac_address)
    os_info = fingerprint.get_os(mac_address)

    device_info["vendor"] = vendor_info
    device_info["os"] = os_info

    return device_info


def main():
    """
    同一ネットワークに接続されているすべての機器のMacアドレスを取得し、そこから端末のベンダー情報とos情報を調べる
    """

    network = "192.168.1.0/24"
    mac_addresses = get_mac_addresses(network)
    if mac_addresses:
        for mac_address in mac_addresses:
            device_info = get_device_info(mac_address)

            print("Macアドレス: " + mac_address)
            print("ベンダー: " + device_info["vendor"])
            print("OS: " + device_info["os"])
    else:
        print("ネットワーク上にデバイスは検出されませんでした。")


if __name__ == "__main__":
    main()
