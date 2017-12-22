#!/usr/bin/env python
from scapy.all import *
from datetime import datetime as dt
from collections import deque
import sys, getopt
import netifaces

class dns_responses:
    def __init__(self, pckid, hostname, answer_count, ip_list):
        self.packet_id = pckid
        self.hostname = hostname
        self.answer_count = answer_count
        self.ip_list = ip_list

dns_responses_list = deque(maxlen=10)

def dns_detect(packet):
    if packet and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):
        udp = packet[UDP]
        dns = packet[DNS]
        if int(udp.sport) != 53 or dns.qr == 0:
            return

        isMatched = False
        isSpoofed = False
        isTypeA = False
        dns_response_iplist = []
        packet_iplist = []

        """Check if the packet has atleast one Type A response"""
        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            if dnsrr.type == 1:
                 isTypeA = True
                 break;
                 
        if isTypeA == False:
            return

        if len(dns_responses_list) > 0:     
             for dns_response in dns_responses_list:
                 if dns_response.packet_id == dns.id and dns_response.hostname == dns.qd.qname.rstrip('.'):
                      isMatched = True 
                      isSpoofed = True   
                      packet_iplist = []          
                      for i in range(dns.ancount):
                          dnsrr = dns.an[i]
                          if dnsrr.type == 1:
                              if dnsrr.rdata in dns_response.ip_list:
                                  isSpoofed = False
                                  break
                              else:
                                  packet_iplist.append(dnsrr.rdata)
                      if isSpoofed == True:
                          dns_response_iplist = dns_response.ip_list
                          break;

        if isMatched == False:
             for i in range(dns.ancount):
                 dnsrr = dns.an[i]
                 if dnsrr.type == 1:
                      packet_iplist.append(dnsrr.rdata)
            
             dns_res = dns_responses(dns.id, dns.qd.qname.rstrip('.'), dns.ancount, packet_iplist)
             
             dns_responses_list.append(dns_res)
             return
        
        if isSpoofed == True:
             print "DNS poisoning attempt"
             print "TXID "+ str(dns.id) + " Request "+ str(dns.qd.qname.rstrip('.'))
             print "Answer1 " + str(packet_iplist)
             print "Answer2 " + str(dns_response_iplist)                     
    
if __name__ == '__main__':
    interface = None
    tracefile = None
    expression = None
    try:
        options, args = getopt.getopt(sys.argv[1:], 'i:r::')
    except getopt.GetoptError:
        print "Invalid option"
        print "dnsdetect [-i interface] [-r tracefile] expression"
        sys.exit()

    for option, arg in options:
        if option == '-i':
            interface = arg
        elif option == '-r':
            tracefile = arg

    if len(args) > 1:
        print "Invalid number of non option arguments given"
        sys.exit()
    elif len(args) == 1:
        expression = args[0]

    if interface == None and tracefile == None:
        gws = netifaces.gateways()
        interface = str(gws['default'][netifaces.AF_INET][1])

    if tracefile != None:
        sniff(filter=expression, offline = tracefile, store=0, prn=dns_detect)
    else:
        sniff(filter=expression, iface = interface, store=0, prn=dns_detect)





