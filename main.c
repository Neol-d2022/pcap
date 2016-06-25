#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#include "ethernet.h"

int main(int argc, char **argv) {
	char errbuf_char[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header_pcap_pkthdr;
	const char *dev = 0;
	pcap_t *p_pcap_t;
	const unsigned char *packet_uchar;
	int res_int;
	unsigned int xmlLevel_uint = 0;
	
	if(argc == 1) dev = "any";
	else if(argc == 2) dev = argv[1];
	else {
		fprintf(stderr, "Usage: pcap_test [Interface]\n");
		return -1;
	}
	
	p_pcap_t = pcap_create(dev, errbuf_char);
	if(!p_pcap_t) {
		fprintf(stderr, "[Error] Cannot create pcap_t.\nError Message: %s\n", errbuf_char);
		return -1;
	}
	
	if((res_int = pcap_activate(p_pcap_t))) {
		fprintf(stderr, "[Error] Cannot activate pcap_t(%d).\n", res_int);
		return -1;
	}
	
	memset(&header_pcap_pkthdr, 0, sizeof(header_pcap_pkthdr));
	while((packet_uchar = pcap_next(p_pcap_t, &header_pcap_pkthdr))) {
		Ethernet_int(packet_uchar, stdout, &xmlLevel_uint, header_pcap_pkthdr.len);
	}
	
	
	return 0;
}