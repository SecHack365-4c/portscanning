from scapy.all import *
from netaddr import *
import sys

#port ip range 
#ARP scan
#TCP scan
#Xmas scan
#UDP scan

#port&ip_range
ip_range = IPRange('203.178.139.246', '203.178.139.246')
for i in ip_range:
    print(i)

port_range= range(17,23)


#check_str(ip_range
def check_host(ip_range):
    for ip in ip_range:
        print(1)
        if sr1(IP(dst=str(ip))/ICMP(),timeout=1,verbose=0):
            print(str(ip) + "is up")
        else:
            print(str(ip) + "is down")
            sys.exit(1)

def dhcp_callback(packet):
   if packet.haslayer(DHCP):
       if packet[DHCP].options[0][1] == 2:
           print("DHCP Offer from {}".format(packet[IP].src))
           print("Gateway: {}".format(packet[BOOTP].siaddr))
           print("Subnet Mask: {}".format(packet[DHCP].options[1][1]))

sniff(filter="udp and (port 67 or 68)", prn=dhcp_callback, store=0)

#syn_scan
def syn_scan(ip_range,port_range):
    
    for port in port_range:
        resp = sr1(
            IP(dst=ip_range)/TCP(dport=port,flags="S"),
            timeout=1,
            verbose=0,
        )
        
        if resp is None:
            print(f"{str(ip_range)}:{port} is filtered")
        
        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                # Send a gratuitous RST to close the connection
                send_rst = sr1(
                    IP(dst=ip_range)/TCP(dport=port,flags="R"),
                    timeout=1,
                    verbose=0
                )
                print(f"{str(ip_range)}:{port} is open.")
            elif (resp.getlayer(TCP).flags == 0x14):
                print(f"{str(ip_range)}:{port} is closed.")
        
        elif(resp.haslayer(ICMP)):
            if(
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
            ):
                print(f"{str(ip_range)}:{port} is filtered (silently dropped).")
            elif(resp.haslayer(TCP)):
                if(resp.getlayer(TCP).flags == 0x12):
                    # Send a gratuitous RST to close the connection
                    send_rst = sr1(
                        IP(dst=ip_range)/TCP(dport=port,flags="R"),
                        timeout=1,
                        verbose=0
                    )
                    print(f"{str(ip_range)}:{port} is open.")
                elif (resp.getlayer(TCP).flags == 0x14):
                    print(f"{str(ip_range)}:{port} is closed.")
        
        elif(resp.haslayer(ICMP)):
            if(
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
            ):
                print(f"{str(ip_range)}:{dst_port} is filtered (silently dropped).")

#ARP scan
def arp_scan(ip_range):
    
    for ip in ip_range:
        request = Ether(dst= 'ff:ff:ff:ff:ff:ff') /ARP(pdst = ip_range)
        ans,unans =srp  (request,timeout=2,verbose=0)
        for sent,received in ans:
            print(received.sprintf(r"%Ether.src% - %ARP.psrc%"))
    
    return

def main():
    check_host(ip_range)
    syn_scan(ip_range,port_range)

if __name__ == "__main__":
     main()