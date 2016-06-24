#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

int main(void) {
	char errbuf_char[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header_pcap_pkthdr;
	pcap_t *p_pcap_t;
	const unsigned char *packet_uchar;
	int res_int;
	unsigned int i_uint;
	
	p_pcap_t = pcap_create("enp0s3", errbuf_char);
	if(!p_pcap_t) {
		fprintf(stderr, "%s", errbuf_char);
		return -1;
	}
	
	if((res_int = pcap_activate(p_pcap_t))) {
		fprintf(stderr, "%d\n", res_int);
	}
	
	memset(&header_pcap_pkthdr, 0, sizeof(header_pcap_pkthdr));
	packet_uchar = pcap_next(p_pcap_t, &header_pcap_pkthdr);
	while((packet_uchar = pcap_next(p_pcap_t, &header_pcap_pkthdr))) {
		//printf("Jacked a packet with length of [%u]\n", header_pcap_pkthdr.len);
		for(i_uint = 0; i_uint < header_pcap_pkthdr.len; i_uint += 1)
			printf("%02hhx  ", packet_uchar[i_uint]);
		printf("\n");
	}
	
	
	return 0;
}