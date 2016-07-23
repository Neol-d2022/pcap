#include <stdio.h>

#include "indent.h"
#include "ppp.h"

int PPPOE_Discovery(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length) {
	unsigned short payloadLength, idx, tlvType, tlvLength, tlvDataUpper, tlvIdx;
	unsigned char code;
	
	if(packet_length < 6) return -1;
	code = packet[1];
	payloadLength = (packet[4] << 8) + packet[5];
	if(payloadLength + 6u > packet_length) return -1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<PPPoE Packet>\n");
	*xmlLevel += 1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Version> %hhu </Version>\n", (unsigned char)(packet[0] >> 4));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Type> %hhu </Type>\n", (unsigned char)(packet[0] & 0x0F));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Code> %hhu </Code>\n", code);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Session ID> %hu </Session ID>\n", (unsigned short)((packet[2] << 8) + packet[3]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Length> %hu </Length>\n", payloadLength);
	
	if(payloadLength) {
		Indent(output, *xmlLevel);
		fprintf(output, "<Tags>\n");
		*xmlLevel += 1;
		
		for(idx = 6; idx < payloadLength; idx += 1) {
			if(idx > payloadLength + 2) return -1;
			tlvType = (packet[idx] << 8) + packet[idx + 1];
			tlvLength = (packet[idx + 2] << 8) + packet[idx + 3];
			tlvDataUpper = idx + 4 + tlvLength;
			if(tlvDataUpper > payloadLength + 6) return -1;
			
			Indent(output, *xmlLevel);
			fprintf(output, "<Tag>\n");
			*xmlLevel += 1;
			
			Indent(output, *xmlLevel);
			fprintf(output, "<Type> %hu </Type>\n", tlvType);
			
			Indent(output, *xmlLevel);
			fprintf(output, "<Length> %hu </Length>\n", tlvLength);
			
			Indent(output, *xmlLevel);
			fprintf(output, "<Value> ");
			for(tlvIdx = idx + 4; tlvIdx < tlvDataUpper; tlvIdx += 1) {
				fprintf(output, "%02hhx ", packet[tlvIdx]);
			}
			fprintf(output, "</Value>\n");
			
			*xmlLevel -= 1;
			Indent(output, *xmlLevel);
			fprintf(output, "</Tag>\n");
			
			idx = tlvDataUpper;
		}
		
		*xmlLevel -= 1;
		Indent(output, *xmlLevel);
		fprintf(output, "</Tags>\n");
	}
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</PPPoE Packet>\n");
	return 0;
}

int PPPOE_Session(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length) {
	unsigned short payloadLength;
	unsigned char code;
	
	if(packet_length < 6) return -1;
	code = packet[1];
	payloadLength = (packet[4] << 8) + packet[5];
	if(payloadLength + 6u > packet_length) return -1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<PPPoE Packet>\n");
	*xmlLevel += 1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Version> %hhu </Version>\n", (unsigned char)(packet[0] >> 4));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Type> %hhu </Type>\n", (unsigned char)(packet[0] & 0x0F));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Code> %hhu </Code>\n", code);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Session ID> %hu </Session ID>\n", (unsigned short)((packet[2] << 8) + packet[3]));
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Length> %hu </Length>\n", payloadLength);
	
	PPP(packet + 6, output, xmlLevel, payloadLength);
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</PPPoE Packet>\n");
	return 0;
}