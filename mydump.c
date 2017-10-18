#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pcap.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <time.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

struct packetdetails
{
	long time_in_usecs;
	u_char ether_dhost[6];
	u_char ether_shost[6];
	char* time_stamp;
	char* ether_type;
	int	ether_type_value;
	int packet_len;
	char* src_ip;
	char* dst_ip;
	int src_port;		
	int dst_port;
	char* protocol_type;
	char* payload;
	int size_payload;
};

void initializePacketDetails(struct packetdetails **packet)
{
	if((*packet))
		(*packet)->time_stamp = 0;
		(*packet)->time_in_usecs = 0;
		(*packet)->ether_type = NULL;
		(*packet)->ether_type_value = 0;
		(*packet)->packet_len = 0;
		(*packet)->src_ip = NULL;
		(*packet)->dst_ip = NULL;
		(*packet)->src_port = 0;
		(*packet)->dst_port = 0;
		(*packet)->protocol_type = NULL;
		(*packet)->payload = NULL;
		(*packet)->size_payload = 0;
		memset((*packet)->ether_dhost, 0, sizeof((*packet)->ether_dhost));
		memset((*packet)->ether_shost, 0, sizeof((*packet)->ether_shost));		 
}

void print_line(const u_char *payload, int len)
{
	int i;
	int gap;
	const u_char *ch;
	
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
	}
	
	// fill the line with spaces if it is less than 16 bytes
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	// print the ASCII character
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/* print packet payload data*/
void print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			
	int line_len;				
	const u_char *ch = payload;

	if (len <= 0)
		return;

	// If the length of the data is less tahn 16bytes
	if (len <= line_width) {
		print_line(ch, len);
		return;
	}

	// If the length of the data is more than 16bytes
	while(1) {
		line_len = line_width % len_rem;
		print_line(ch, line_len);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		if (len_rem <= line_width) {
			print_line(ch, len_rem);
			break;
		}
	}

return;
}

u_char* strStr(u_char* payload, u_char* filter_payload)
{
	while(*payload)
	{
		int len = 0;
		u_char* str = payload;
		u_char* substr = filter_payload;	
		
		while(*payload && *substr && *substr == *payload)
		{
			len++;
			payload++;
			substr++;
		}
		payload = payload - len;
		if(!*substr)
		{
			return payload;
		}
		payload = str + 1;
	}
    return NULL;	
}

char* remove_non_printable_chars(char *payload, int length){
	char *payload_ch= payload;
	char *newpayload = payload;
	int i;
	for(i = 0; i < length; i++){
		if (!isprint(*payload_ch))
				*payload_ch='.';
		payload_ch++;
	}
	return newpayload;
}

void print_packet(struct packetdetails *packet, u_char* string_filter_payload, u_char* error_message)
{
	char buf[80];
	u_char* ptr;
	int i;
	if(string_filter_payload != NULL)
	{	
		if(packet->payload != NULL)
      	{
      	  	if(strStr(remove_non_printable_chars(packet->payload, packet->size_payload), string_filter_payload) == NULL)
	  		  	return;
	  	}	
		else
			return;	    
	}

	printf("\n%s.%06ld", packet->time_stamp, packet->time_in_usecs);
	
	//Source MAC Address and Destination MAC address
	ptr = packet->ether_shost;
    i = ETHER_ADDR_LEN;
    do
	{
        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);

    ptr = packet->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf(" ->");
    do
	{
        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
	
	printf(" %s 0x%x len %d ", packet->ether_type, packet->ether_type_value, packet->packet_len);
	
	if(error_message == NULL)
	{
		if(packet->ether_type == "IP")
			if(packet->protocol_type == "TCP" || packet->protocol_type == "UDP")
				printf("%s:%d -> %s:%d %s\n", packet->src_ip, packet->src_port, packet->dst_ip, packet->dst_port, packet->protocol_type);
            else
                printf("%s -> %s %s\n", packet->src_ip, packet->dst_ip, packet->protocol_type);
		
			if (packet->size_payload > 0) 
			{
				print_payload(packet->payload, packet->size_payload);
			}
		else
		    printf("\n");	
	}
		
	if(error_message)
	    printf(" %s\n", error_message);
}

/* Get the sniffed packet details*/
void get_packet_details(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{	
	int i;
	u_char *ptr;
    u_char* string_filter_payload = args;
	// declare pointers to packet headers 
	struct ip* iphdr = NULL;                       //IP Header
    struct icmphdr* icmphdr = NULL;                //ICMP Header
    struct tcphdr* tcphdr = NULL;                  //TCP Header
    struct udphdr* udphdr = NULL;                  //UDP Header
    struct ether_header* ethhdr = NULL;            //Ethernet Header
    struct packetdetails* packet_details = (struct packetdetails*)malloc(sizeof(struct packetdetails));
    u_char* error_message = NULL;
	int size_ip;
	int size_tcp;

    initializePacketDetails(&packet_details);
    
    packet_details->src_ip = (char*)malloc(80);
    packet_details->dst_ip = (char*)malloc(80);
    
    char buf[80];

	struct tm ts = *localtime(&(header->ts.tv_sec));
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
    packet_details->time_stamp = buf;
    packet_details->time_in_usecs = (long)header->ts.tv_usec;

	packet_details->packet_len = header->caplen;
				
	// define ethernet header 
	ethhdr = (struct ether_header*)(packet);
	packet_details->ether_type_value = ntohs(ethhdr->ether_type); 
    
    for (i = 0; i < 6; i++) {
      packet_details->ether_dhost[i] = ethhdr->ether_dhost[i];
   }
   
   for (i = 0; i < 6; i++) {
      packet_details->ether_shost[i] = ethhdr->ether_shost[i];
   }
    
	//Ethernet Type
    if (ntohs (ethhdr->ether_type) == ETHERTYPE_IP)
    {
    	packet_details->ether_type = "IP";
    }
	else if (ntohs (ethhdr->ether_type) == ETHERTYPE_ARP)
    {
    	packet_details->ether_type = "ARP";
    }
	else 
	{
		packet_details->ether_type = "Unknown ethertype";
        goto end;
    }	
	    
    // IP Packet    
    if (ntohs (ethhdr->ether_type) == ETHERTYPE_IP)
    {
    	// define/compute ip header offset 
		iphdr = (struct ip*)(packet + SIZE_ETHERNET);
		size_ip = 4*(iphdr->ip_hl);
		if (size_ip < 20) 
		{
			error_message = "Invalid IP header length";
			goto end;
		}
		
		memcpy(packet_details->src_ip, inet_ntoa(iphdr->ip_src), 80);
		memcpy(packet_details->dst_ip, inet_ntoa(iphdr->ip_dst), 80);
	    
		// determine protocol 	
		switch(iphdr->ip_p) {
			case IPPROTO_TCP:
				packet_details->protocol_type = "TCP";
				
				//compute tcp header offset 
				tcphdr = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp= ((*((uint16_t *)(tcphdr + 12)) & 0xF0)>>4)*4;
				if (size_tcp < 20) {
					error_message = "Invalid TCP header length";
					goto end;
				}
			    
			    packet_details->src_port = ntohs(tcphdr->th_sport);
			    packet_details->dst_port = ntohs(tcphdr->th_dport);
				
				// Payload
				packet_details->payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
				packet_details->size_payload = header->caplen -(SIZE_ETHERNET + size_ip + size_tcp);
				
				break;
				
			case IPPROTO_UDP:
				packet_details->protocol_type = "UDP";
				
				udphdr = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
				packet_details->src_port = ntohs(udphdr->uh_sport);
			    packet_details->dst_port = ntohs(udphdr->uh_dport);
				
				//Payload
				packet_details->payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(udphdr));
				packet_details->size_payload = header->caplen -(SIZE_ETHERNET + size_ip + sizeof(udphdr));
				
				break;
				
			case IPPROTO_ICMP:
				packet_details->protocol_type = "ICMP";
				icmphdr = (struct icmphdr *)(packet + SIZE_ETHERNET + size_ip);
				
				//Payload
				packet_details->payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(icmphdr));
				packet_details->size_payload = header->caplen -(SIZE_ETHERNET + size_ip + sizeof(icmphdr));
				break;
			
			default:
				packet_details->protocol_type = "Unknown protocol";
				packet_details->payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
				packet_details->size_payload = header->caplen -(SIZE_ETHERNET + size_ip);
				break;
		}
	}
	
end:	
	print_packet(packet_details, string_filter_payload, error_message);
	if(packet_details)
		free(packet_details->src_ip);
		free(packet_details->dst_ip);
	    free(packet_details);
	    packet_details = NULL;
	    
	return;
}

/*Sniff the packet*/
void sniff_packet(char *filename, char *interface, char *string, char *expression)
{
	char *dev = NULL;			        //Capture device name
	char errbuf[PCAP_ERRBUF_SIZE];		//Error buffer
	pcap_t *handle;				        // Packet capture handle 

	char filter_exp[4];		            // BPF filter expression 
	struct bpf_program fp;			    // Filter packets (expression) 
	bpf_u_int32 mask;			        // Subnet mask 
	bpf_u_int32 net;			        // IP
	 
	if ((filename != NULL))
	{
		//open file and create pcap handler
     	handle = pcap_open_offline(filename, errbuf);
     	if (handle == NULL) {
    		fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
    		exit(EXIT_FAILURE);
		}
	}
	else
	{
		if(interface == NULL)
		{
			// find a capture device if not specified on command-line 
			dev = pcap_lookupdev(errbuf);
			if (dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
				exit(EXIT_FAILURE);
			}
		}
		else
		{
			dev = interface;
		}
		
		// get network number and mask associated with capture device 
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
	
		// open captured device 
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}
	
		// Check if we are capturing on an Ethernet device 
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}	    
	}
	
	if(expression != NULL)
	{
		strcpy( filter_exp, expression);
		// compile the filter expression 
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	
		// apply the compiled filter 
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}
  
	// Callback function will get called
	pcap_loop(handle, -1, get_packet_details, (u_char*)string);

	pcap_close(handle);
	printf("\nCapture complete.\n");
	return;
}

int main(int argc, char **argv)
{
	int helpFlag = 0;
	char *fileName = NULL;
	char *deviceInterface = NULL;
	char *expression = NULL;
	char *stringPattern = NULL;
  	int index;
  	int c;
	int count;
    opterr = 0;

	while ((c = getopt (argc, argv, "i:r:s:h")) != -1)
	{
		switch (c)
		{
			case 'i':
				deviceInterface = optarg;
				break;
			case 'r':
				fileName = optarg;
				break;
			case 's':
				stringPattern = optarg;
				break;
			case 'h':
				helpFlag = 1;
				break;	
			case '?':
				if (optopt == 'i' || optopt == 'r' || optopt == 's')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
				fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				exit(EXIT_FAILURE);
			default:
				abort ();
		}
	}
  
    for (index = optind; index < argc; index++)
    {
    	count ++;
	}
    
	if(count > 1)
	{
		printf("Invalid number of non option arguments.\n");	
		exit(EXIT_FAILURE);
	}	
	else
	{
		index = optind;
		expression = argv[index];
	}

	if(helpFlag)
	{
		printf("Usage:\n");
		printf("mydump [-i interface] [-r file] [-s string] expression [-h]]\n");
		printf("-i     Capture packets from the network device <interface> (e.g., eth0). If not specified, mydump should automatically select a default interface to listen on\n");
		printf("-r     Read packets from <file> in tcpdump format\n");       
		printf("-s     Display packets that contain <string> in their payload\n");
		printf("<expression>   BPF filter that specifies which packets will be dumped. If no filter is given, all packets seen on the interface (or contained in the trace) should be dumped. Otherwise, only packets matching <expression> should be dumped\n");		
        printf("-h     Displays the help message\n");
		exit(EXIT_FAILURE);
	}

    sniff_packet(fileName, deviceInterface, stringPattern, expression);    
	return 0;
}
