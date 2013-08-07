/*
 ============================================================================
 Name        : PacketSniffer.c
 Author      : Samuel Harte
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/ip6.h"
#include "/usr/include/pcap/pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

/*packet handler*/
void my_callback(u_char *, const struct pcap_pkthdr * , const u_char * );

/*Type*/
void call_IPv4(const u_char *);
void call_IPv6(const u_char *);

/*Protocol*/
void call_TCP_P (const u_char *);
void call_UDP_P (const u_char *);
void call_ICMP_P(const u_char *);
void call_IPv6_P(const u_char *, int);

/*Payload*/
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);
void sizeof_payload(const u_char *, int, int);

const char *payload;

int main
(int args, char *argv[])	// variables to be used later
{
	printf("Start Program\n");

	// Start a capture
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];		// pcap error buffer

	//	(offline)
	// tcp dump filename
	const char *fname = "/u/students/hartesamu/workspace/NWEN 302/PacketSniffer/http.pcap";
	descr = pcap_open_offline (fname, errbuf);
	if(descr == NULL){
		printf("pcap open offline failed\n");
		return 1;
	}
	/**/

	// Call pcap loop
	//pcap_loop(descr, /*atoi(argv[1])*/0, my_callback, /*args*/NULL);
	printf("enter loop\n");
	if(pcap_loop(descr, /*atoi(argv[1])*/0, my_callback, /*args*/NULL) < 0){
		printf("pcap failed!\n");
		return 1;
	}
	pcap_close(descr);


	//struct iphdr *ipptr; 			/* net/ipptr.h */

	puts("End Program");
	return EXIT_SUCCESS;
}

void my_callback
(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	static int count = 1;
	// Reading packet data
	struct ether_header *ethdr;  	/* net/ethernet.h */

	/* lets start with the ether header... */
	ethdr = (struct ether_header*) packet;

	printf("Packet number %i:\n", count);
	switch (ntohs(ethdr->ether_type)){
	case ETHERTYPE_IP:
		printf("======IPv4======\n");
		call_IPv4(packet);
		printf("\n");
		break;
	case ETHERTYPE_VLAN:
		printf("======VLAN======\n");
		printf("\n");
		break;
	case ETHERTYPE_IPV6:
		printf("======IPv6======\n");
		call_IPv6(packet);
		printf("\n");
		break;
	default:
		printf("====Unknown=====\n");
		printf("\n");
		break;
	}
	count++;

	// Pause at
	char c;	if(count > 825) scanf("Wait %c", &c);
}

/*===========================PACKET_TYPE===========================*/
/*=================================================================*/

void call_IPv4(const u_char *packet){
	const struct ip* ipHeader;
	ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

	printf(" Ether Type: IPv4\n");
	printf("       From: %s\n", inet_ntoa(ipHeader->ip_src));
	printf("         To: %s\n", inet_ntoa(ipHeader->ip_dst));
	/*switch(ipHeader->ip_p){
	case IPPROTO_TCP:
		call_TCP_P(packet);
		break;
	case IPPROTO_UDP:
		call_UDP_P(packet);
		break;
	case IPPROTO_ICMP:
		call_ICMP_P(packet);
		break;
	default:
		break;
	}*/
	int offset = 0;
	const struct tcphdr* tcpHeader;
	const struct udphdr* udpHeader;
	const struct icmp* icmpHeader;

	switch(ipHeader->ip_p){
	case IPPROTO_TCP:
		tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		printf("   Protocol: TCP\n");
		printf("   Src port: %i\n", ntohs(tcpHeader->source));
		printf("   Dst port: %i\n", ntohs(tcpHeader->dest));
		offset = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		printf("   Protocol: UDP\n");
		printf("   Src port: %i\n", ntohs(udpHeader->source));
		printf("   Dst port: %i\n", ntohs(udpHeader->dest));
		offset = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		icmpHeader = (struct icmp*) (packet + sizeof(struct ether_header) + sizeof(struct ip));
		printf("   Protocol: ICMP\n");
		offset = sizeof(struct icmp);
		break;
	default:
		return;
	}

	/* compute tcp payload (segment) size */
	sizeof_payload(packet, ntohs(ipHeader->ip_len) - (sizeof(struct ip) + sizeof(struct tcphdr)),
			(sizeof(struct ether_header) + sizeof(struct ip) + offset));
}

void call_IPv6(const u_char *packet){
	const struct ip6_hdr* ip6Header;
	ip6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

	char straddr[INET6_ADDRSTRLEN];

	printf(" Ether Type: IPv6\n");
	printf("       From: %s\n", inet_ntop(AF_INET6, &ip6Header->ip6_src, straddr, sizeof(straddr)));
	printf("         To: %s\n", inet_ntop(AF_INET6, &ip6Header->ip6_dst, straddr, sizeof(straddr)));

	struct ip6_ext *ipExt;
	int numOfExt = 0;
	int extLength = 0;
	int payload_offset = 0;
	u_char ipSkipExt;

	ipSkipExt = ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

	while(1){
		if(ipSkipExt == IPPROTO_TCP || ipSkipExt == IPPROTO_ICMPV6 || ipSkipExt == IPPROTO_UDP) break;
		if(ipSkipExt == 0x3B || ipSkipExt == 0x58) break;
		numOfExt++;
		switch (ipSkipExt){
		case IPPROTO_DSTOPTS:
			printf("         %i: Destination EXTENSION HEADER\n", numOfExt);
			break;
		case IPPROTO_HOPOPTS:
			printf("         %i: Hop by Hop EXTENSION HEADER\n", numOfExt);
			break;
		case IPPROTO_ROUTING:
			printf("         %i: Routing EXTENSION HEADER\n", numOfExt);
			break;
		default:
			printf("         %i: OTHER EXTENSION HEADER\n", numOfExt);
			break;
		}
		// pointer to the header
		int size6 = (sizeof(struct ip6_ext) * numOfExt);
		ipExt = (struct ip6_ext*)(packet+sizeof(struct ether_header)
				+sizeof(struct ip6_hdr)+(sizeof(struct ip6_ext) * numOfExt));
		ipSkipExt = ipExt->ip6e_nxt;	// pointer to the next header
		extLength = ipExt->ip6e_len;	// length of the protocol
		payload_offset = payload_offset + 8 +(8*extLength);	// sum of the protocols size
	}

	const struct tcphdr* tcpHeader;
	const struct udphdr* udpHeader;
	const struct icmp6_hdr* icmp6Header;
	switch(ipSkipExt){
	case IPPROTO_ICMPV6:
		icmp6Header = (struct icmp6_hdr*)(packet + sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct ip6_ext)*numOfExt);
		printf("   Protocol: ICMPv6\n");
		break;
	case IPPROTO_TCP:
		tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct ip6_ext)*numOfExt);
		printf("   Protocol: TCP\n");
		printf("   Src port: %i\n", ntohs(tcpHeader->source));
		printf("   Dst port: %i\n", ntohs(tcpHeader->dest));
		break;
	case IPPROTO_UDP:
		udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header)+sizeof(struct ip6_hdr)+sizeof(struct ip6_ext)*numOfExt);
		printf("   Protocol: UDP\n");
		printf("   Src port: %i\n", ntohs(udpHeader->source));
		printf("   Dst port: %i\n", ntohs(udpHeader->dest));
		break;
	default:
		printf("   Protocol: UNKNOWN\n");
		break;
	}

	sizeof_payload(packet, ntohs(ip6Header->ip6_ctlun.ip6_un1.ip6_un1_plen),
			sizeof(struct ether_header)+sizeof(struct ip6_hdr)+payload_offset+sizeof(struct icmp6_hdr));
}

/*===========================PROTOCOLS===========================*/
/*===============================================================*/

void call_TCP_P(const u_char *packet){
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
	ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
	tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

	printf("   Protocol: TCP\n");
	printf("   Src port: %i\n", ntohs(tcpHeader->source));
	printf("   Dst port: %i\n", ntohs(tcpHeader->dest));

	/* compute tcp payload (segment) size */
	sizeof_payload(packet, ntohs(ipHeader->ip_len) - (sizeof(struct ip) + sizeof(struct tcphdr)),
			(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)));
}

void call_UDP_P(const u_char *packet){
	const struct ip* ipHeader;
	const struct udphdr* udpHeader;
	ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
	udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

	printf("   Protocol: UDP\n");
	printf("   Src port: %i\n", ntohs(udpHeader->source));
	printf("   Dst port: %i\n", ntohs(udpHeader->dest));

	/* compute udp payload (segment) size */
	sizeof_payload(packet, ntohs(ipHeader->ip_len) - (sizeof(struct ip) + sizeof(struct udphdr)),
			(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)));
}

void call_ICMP_P(const u_char *packet){
	const struct ip* ipHeader;
	const struct icmp* icmpHeader;
	ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
	icmpHeader = (struct icmp*) (packet + sizeof(struct ether_header) + sizeof(struct ip));

	printf("   Protocol: ICMP\n");

	/* compute icmp payload (segment) size */
	sizeof_payload(packet, ntohs(ipHeader->ip_len) - (sizeof(struct ip) + sizeof(struct icmp)),
			(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmp)));
}

void call_IPv6_P(const u_char *packet, int offset){

}

/*===========================PRINT_PAYLOAD===========================*/
/*===================================================================*/

/* Code taken from
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset){
	int i;
	int gap;
	const u_char *ch;
	/* offset */
	printf("%05d   ", offset);
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	/* ascii (if printable) */
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

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
 * Print payload data; it might be binary, so don't just
 * treat it as a string.
 */
void sizeof_payload(const u_char *packet, int payload_size, int payload_offset){

	payload = (u_char *)(packet+payload_offset);

	if (payload_size > 0)
	{
		printf("    Payload:(%d bytes)\n", payload_size);
		print_payload(payload, payload_size);
	}else{
		printf("NO PAYLOAD WAS FOUND\n");
	}
}

