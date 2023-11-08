import nmap


def scan_network(network):
    nm = nmap.PortScanner()
    nm.scan(
        network, arguments="-A"  # -AでOSの種類とそのバージョンを検知する事が出来ます。
    )  # オプションでOSの種類とそのバージョンを検知する事が出来ます。OSの検出には特権が必要になります。
    if nm.all_hosts() == []:
        print("no hosts found")
    for host in nm.all_hosts():
        # print(host)
        if nm[host].state() == "up":
            print("Host : %s" % host)
            print("OS details : %s" % nm[host]["osmatch"])


scan_network("131.206.251.0/24")  # 速度がとても遅いので注意してください。
