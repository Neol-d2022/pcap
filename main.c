#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#include "ethernet.h"

int main(void) {
	char errbuf_char[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header_pcap_pkthdr;
	pcap_t *p_pcap_t;
	const unsigned char *packet_uchar;
	int res_int;
	unsigned int xmlLevel_uint = 0;
	
	p_pcap_t = pcap_create("enp0s3", errbuf_char);
	if(!p_pcap_t) {
		fprintf(stderr, "%s", errbuf_char);
		return -1;
	}
	
	if((res_int = pcap_activate(p_pcap_t))) {
		fprintf(stderr, "%d\n", res_int);
	}
	
	memset(&header_pcap_pkthdr, 0, sizeof(header_pcap_pkthdr));
	while((packet_uchar = pcap_next(p_pcap_t, &header_pcap_pkthdr))) {
		Ethernet_int(packet_uchar, stdout, &xmlLevel_uint, header_pcap_pkthdr.len);
	}
	
	
	return 0;
}