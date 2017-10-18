# Network-Packet-Sniffer
A passive network monitoring application written in C, as part of graduate course on Network Security

The program will capture the traffic from a network interface in promiscuous mode (or read the packets from a pcap trace file) and print a record for each packet in its standard output, much like a simplified version of tcpdump. The user can specify a BPF filter for capturing a subset of the traffic, and/or a string pattern for capturing only packets with matching payloads

The program has the following specification:

mydump [-i interface] [-r file] [-s string] expression

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump should automatically select a default interface to
    listen on (hint 1). Capture should continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format (hint 2).

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied). You are not required to implement wildcard or regular
    expression matching. A simple string matching operation should suffice
    (hint 3).

<expression> is a BPF filter that specifies which packets will be dumped. If
no filter is given, all packets seen on the interface (or contained in the
trace) should be dumped. Otherwise, only packets matching <expression> should
be dumped.
  
For each packet, mydump prints a record containing the timestamp, source and
destination MAC address, EtherType, packet length, source and destination IP
address and port, protocol type (e.g., "TCP", "UDP", "ICMP", "OTHER"), and the
raw content of the packet payload  
