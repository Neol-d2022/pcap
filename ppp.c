#include <stdio.h>

#include "indent.h"
#include "ip.h"

int PPP(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length) {
	unsigned short idx = 0;
	
	if(packet_length < 6) {
		fprintf(output, "%u/6.\n", packet_length);
		return -1;
	}
	
	Indent(output, *xmlLevel);
	fprintf(output, "<PPP Packet>\n");
	*xmlLevel += 1;
	
	if(packet[idx] == 0x7E) {
		fprintf(output, "<Flag> 0x7E </Flag>\n");
		idx = 1;
	}
	else { }//Flag omitted
	
	if(packet[idx] != 0xff) { //address omitted
		Indent(output, *xmlLevel);
		fprintf(output, "<Control> 0x%02hhX </Control>\n", packet[idx]);
		
		idx += 1;
	}
	else {
		Indent(output, *xmlLevel);
		fprintf(output, "<Address> 0xFF </Address>\n");
		
		Indent(output, *xmlLevel);
		fprintf(output, "<Control> 0x%02hhX </Control>\n", packet[idx + 1]);
		
		idx += 2;
	}
	
	switch(packet[idx]) {
		case 0x21: {
			Indent(output, *xmlLevel);
			fprintf(output, "<Protocol> 0x0021 </Protocol>\n");
			IP(packet + idx + 1, output, xmlLevel, packet_length - idx - 1);
			break;
		}
		default: {
			Indent(output, *xmlLevel);
			fprintf(output, "<Data>");
			
			for(; idx < packet_length; idx += 1)
				fprintf(output, "%02hhx ", packet[idx]);
			
			fprintf(output, "</Data>\n");
			break;
		}
	}
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</PPP Packet>\n");
	return 0;
}