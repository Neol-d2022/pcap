#include <stdio.h>

#include "indent.h"

int TCP(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length) {
	unsigned short headerLength, payloadLength, idx;
	
	if(packet_length < 20) return -1;
	headerLength = (packet[12] & 0xF0) >> 2;
	//fprintf(stderr, "%hu / %u\n", headerLength, packet_length);
	if(headerLength > packet_length) return -1;
	payloadLength = packet_length - headerLength;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<TCP Packet>\n");
	*xmlLevel += 1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Src Port> %hu </Src Port>\n", (unsigned short)((packet[0] << 8) + packet[1]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Dst Port> %hu </Dst Port>\n", (unsigned short)((packet[2] << 8) + packet[3]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Seq> %hu </Seq>\n", (unsigned int)((packet[4] << 24) + (packet[5] << 16) + (packet[6] << 8) + packet[7]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Ack> %hu </Ack>\n", (unsigned int)((packet[8] << 24) + (packet[9] << 16) + (packet[10] << 8) + packet[11]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Data Offset> %hhu </Data Offset>\n", (unsigned char)(headerLength >> 2));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Flags>\n");
	*xmlLevel += 1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<NS> %hhu </NS>\n", (unsigned char)(packet[12] & 0x01));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<CWR> %hhu </CWR>\n", (unsigned char)((packet[13] & 0x80) >> 7));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<ECE> %hhu </ECE>\n", (unsigned char)((packet[13] & 0x40) >> 6));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<URG> %hhu </URG>\n", (unsigned char)((packet[13] & 0x20) >> 5));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<ACK> %hhu </ACK>\n", (unsigned char)((packet[13] & 0x10) >> 4));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<PSH> %hhu </PSH>\n", (unsigned char)((packet[13] & 0x08) >> 3));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<RST> %hhu </RST>\n", (unsigned char)((packet[13] & 0x04) >> 2));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<SYN> %hhu </SYN>\n", (unsigned char)((packet[13] & 0x02) >> 1));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<FIN> %hhu </FIN>\n", (unsigned char)(packet[13] & 0x01));
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</Flags>\n");
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Windows Size> %hu </Windows Size>\n", (unsigned short)((packet[14] << 8) + packet[15]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Checksum> %hu </Checksum>\n", (unsigned short)((packet[16] << 8) + packet[17]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Urgent Ptr> %hu </Urgent Ptr>\n", (unsigned short)((packet[18] << 8) + packet[19]));
	
	if(headerLength > 20) {
		Indent(output, *xmlLevel);
		fprintf(output, "<Option Data> ");
		for(idx = 20; idx < headerLength; idx += 1) {
			fprintf(output, "%02hhx ", packet[idx]);
		}
		fprintf(output, "</Option Data>\n");
	}
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Payload Data> ");
	for(idx = headerLength; idx < packet_length; idx += 1) {
		fprintf(output, "%02hhx ", packet[idx]);
	}
	fprintf(output, "</Payload Data>\n");
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</TCP Packet>\n");
	
	return 0;
}