#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#include "ethernet.h"

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pres;
	const char *dev = 0;
	pcap_t *p;
	const unsigned char *packet;
	int res;
	unsigned int xmlLevel = 0;
	
	if(argc == 1) dev = "any";
	else if(argc == 2) dev = argv[1];
	else {
		fprintf(stderr, "Usage: pcap_test [Interface]\n");
		return -1;
	}
	
	p = pcap_create(dev, errbuf);
	if(!p) {
		fprintf(stderr, "[Error] Cannot create pcap_t.\nError Message: %s\n", errbuf);
		return -1;
	}
	
	if((res = pcap_activate(p))) {
		fprintf(stderr, "[Error] Cannot activate pcap_t(%d).\n", res);
		return -1;
	}
	
	memset(&pres, 0, sizeof(pres));
	while((packet = pcap_next(p, &pres))) {
		Ethernet(packet, stdout, &xmlLevel, pres.len);
	}
	
	
	return 0;
}