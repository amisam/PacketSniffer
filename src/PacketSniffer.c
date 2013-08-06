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
#include "/usr/include/pcap/pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

int main(int argc, char *argv[]) {
	puts("Start Program");

	// Compile the filter
	struct bpf_program fp;
	pcap_t* iface;
	bpf_u_int32 netp;
	pcap_compile(iface, &fp, argv[2], 0, netp);

	// Set the filter
	pcap_setfilter(iface, &fp);

	// Start a capture
					//	(online)
	p_t* iface;
	success = pcap_findalldevs(&ifaceList ,errbuf);
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);

					//	(offline)
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_open_offline(const char *fname, char *errbuf);

	// Call pcap loop
	void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){}
	pcap_loop(iface,atoi(argv[1]), my_callback, args);

	// Reading packet data
	my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
	struct ether_header *eptr;  		/* net/ethernet.h */
	struct iphdr *ipptr; 		/* net/ipptr.h */
	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;
	fprintf(stdout,"ethernet header source: %s", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));

	puts("End Program");
	return EXIT_SUCCESS;
}
