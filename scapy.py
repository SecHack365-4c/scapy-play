from scapy.all import *
from netaddr import *
import sys

#port ip range 
#ARP scan
#TCP scan
#Xmas scan
#UDP scan

#port range
ip_range = IPRange('192.168.1.0', '192.168.1.20')
for i in ip_range:
    //ip_range内のipを指定できる
    
start_port = 1
end_port = 100
port_range = range(start_port, end_port + 1)

#check host
def check_host:
    for ip in ip_range:
        if sr1(IP(dst=str(ip))/ICMP(),timeout=1,verbose=0):
            print(str(ip) + "is up")
        else:
            print(str(ip) + "is down")
            sys(1)
#syn scan
def syn_scan(target,ports):
    for i in port_range:
        response = sr1(
            IP(dst=target)/TCP(dport=i,flags="S"),timeout=1,verbose=0
        )
        
        if response in None:
            print(f"{target}:{i} is filtered")
        
        elif(response.haslayer(TCP)):
        
            if(resp.getlayer(TCP).flags == 0x12):
                        # Send a gratuitous RST to close the connection
                        send_rst = sr(
                            IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                            timeout=1,
                            verbose=0,
                        )
                        print(f"{host}:{dst_port} is open.")

            elif (resp.getlayer(TCP).flags == 0x14):
                        print(f"{host}:{dst_port} is closed.")
        
    elif(resp.haslayer(ICMP)):
        if(
            int(resp.getlayer(ICMP).type) == 3 and
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
        ):
            print(f"{host}:{dst_port} is filtered (silently dropped).")