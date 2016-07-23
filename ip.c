#include <stdio.h>
#include <stdlib.h>

#include "indent.h"
#include "tcp.h"
#include "udp.h"

int IP(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length) {
	unsigned short totalLength, payloadLength, headerLength, idx;
	unsigned char proto, ihl;
	//unsigned char cpy, optNum, optLen;
	
	if(packet_length < 20) return -1;
	ihl = *packet & 0x0F;
	totalLength = (packet[2] << 8) + packet[3];
	if(totalLength > packet_length) return -1;
	headerLength = ihl << 2;
	if(headerLength > totalLength) return -1;
	payloadLength = totalLength - headerLength;
	proto = packet[9];
	
	Indent(output, *xmlLevel);
	fprintf(output, "<IP Packet>\n");
	
	*xmlLevel += 1;
	Indent(output, *xmlLevel);
	fprintf(output, "<Version> %hhu </Version>\n", (unsigned char)(*packet >> 4));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<IHL> %hhu </IHL>\n", ihl);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<DSCP> %hhu </DSCP>\n", (unsigned char)(packet[1] >> 2));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<ECN> %hhu </ECN>\n", (unsigned char)(packet[1] & 0x03));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Total Length> %hu </Total Length>\n", totalLength);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Identification> %hu </Identification>\n", (unsigned short)((packet[4] << 8) + packet[5]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Flags>\n");
	*xmlLevel += 1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<DF> %hhu </DF>\n", (unsigned char)((packet[6] & 0x40) >> 6));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<MF> %hhu </MF>\n", (unsigned char)((packet[6] & 0x20) >> 5));
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</Flags>\n");
	
	Indent(output, *xmlLevel);
	fprintf(output, "<FO> %hu </FO>\n", (unsigned short)(((packet[6] & 0x1F) << 8) + packet[7]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<TTL> %hhu </TTL>\n", packet[8]);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Protocol> %hhu </Protocol>\n", proto);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Header Checksum> %hu </Header Checksum>\n", (unsigned short)((packet[10] << 8) + packet[11]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Src IP Addr> %hhu.%hhu.%hhu.%hhu </Src IP Addr>\n", packet[12], packet[13], packet[14], packet[15]);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Dst IP Addr> %hhu.%hhu.%hhu.%hhu </Dst IP Addr>\n", packet[16], packet[17], packet[18], packet[19]);
	
	if(headerLength > 20) {
		Indent(output, *xmlLevel);
		fprintf(output, "<Option Data> ");
		for(idx = 20; idx < headerLength; idx += 1) {
			fprintf(output, "%02hhx ", packet[idx]);
		}
		fprintf(output, "</Option Data>\n");
	}
	
	switch(proto) {
		/*case 1: {
			
		}*/
		case 6: {
			TCP(packet + headerLength, output, xmlLevel, payloadLength);
			break;
		}
		
		case 17: {
			UDP(packet + headerLength, output, xmlLevel, payloadLength);
			break;
		}
		default: {
			Indent(output, *xmlLevel);
			fprintf(output, "<Payload Data> ");
			for(idx = headerLength; idx < totalLength; idx += 1) {
				fprintf(output, "%02hhx ", packet[idx]);
			}
			fprintf(output, "</Payload Data>\n");
		}
	}
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</IP Packet>\n");
	return 0;
}