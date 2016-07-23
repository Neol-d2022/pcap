#include <stdio.h>

#include "indent.h"

int UDP(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length) {
	unsigned short totalLength, idx;
	
	totalLength = (packet[4] << 8) + packet[5];
	if(totalLength < 8 || totalLength > packet_length) return -1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<UDP Packet>\n");
	*xmlLevel += 1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Src Port> %hu </Src Port>\n", (unsigned short)((packet[0] << 8) + packet[1]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Dst Port> %hu </Dst Port>\n", (unsigned short)((packet[2] << 8) + packet[3]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Length> %hu </Length>\n", totalLength);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Checksum> %hu </Checksum>\n", (unsigned short)((packet[6] << 8) + packet[7]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Payload Data> ");
	for(idx = 8; idx < totalLength; idx += 1) {
		fprintf(output, "%02hhx ", packet[idx]);
	}
	fprintf(output, "</Payload Data>\n");
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</UDP Packet>\n");
	return 0;
}