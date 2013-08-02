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

	// Start a capture (offline)


	puts("End Program");
	return EXIT_SUCCESS;
}
