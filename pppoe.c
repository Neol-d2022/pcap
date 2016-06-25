#include <stdio.h>

#include "indent.h"
#include "ppp.h"

int PPPOE_Discovery_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint) {
	unsigned short payloadLength_ushort, idx_ushort, tlvType_ushort, tlvLength_ushort, tlvDataUpper_ushort, tlvIdx_ushort;
	unsigned char code_uchar;
	
	if(packet_length_uint < 6) return -1;
	code_uchar = packet_uchar[1];
	payloadLength_ushort = (packet_uchar[4] << 8) + packet_uchar[5];
	if(payloadLength_ushort + 6u > packet_length_uint) return -1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<PPPoE Packet>\n");
	*xmlLevel_uint += 1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Version> %hhu </Version>\n", (unsigned char)(packet_uchar[0] >> 4));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Type> %hhu </Type>\n", (unsigned char)(packet_uchar[0] & 0x0F));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Code> %hhu </Code>\n", code_uchar);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Session ID> %hu </Session ID>\n", (unsigned short)((packet_uchar[2] << 8) + packet_uchar[3]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Length> %hu </Length>\n", payloadLength_ushort);
	
	if(payloadLength_ushort) {
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Tags>\n");
		*xmlLevel_uint += 1;
		
		for(idx_ushort = 6; idx_ushort < payloadLength_ushort; idx_ushort += 1) {
			if(idx_ushort > payloadLength_ushort + 2) return -1;
			tlvType_ushort = (packet_uchar[idx_ushort] << 8) + packet_uchar[idx_ushort + 1];
			tlvLength_ushort = (packet_uchar[idx_ushort + 2] << 8) + packet_uchar[idx_ushort + 3];
			tlvDataUpper_ushort = idx_ushort + 4 + tlvLength_ushort;
			if(tlvDataUpper_ushort > payloadLength_ushort + 6) return -1;
			
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "<Tag>\n");
			*xmlLevel_uint += 1;
			
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "<Type> %hu </Type>\n", tlvType_ushort);
			
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "<Length> %hu </Length>\n", tlvLength_ushort);
			
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "<Value> ");
			for(tlvIdx_ushort = idx_ushort + 4; tlvIdx_ushort < tlvDataUpper_ushort; tlvIdx_ushort += 1) {
				fprintf(output_FILE, "%02hhx ", packet_uchar[tlvIdx_ushort]);
			}
			fprintf(output_FILE, "</Value>\n");
			
			*xmlLevel_uint -= 1;
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "</Tag>\n");
			
			idx_ushort = tlvDataUpper_ushort;
		}
		
		*xmlLevel_uint -= 1;
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "</Tags>\n");
	}
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</PPPoE Packet>\n");
	return 0;
}

int PPPOE_Session_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint) {
	unsigned short payloadLength_ushort;
	unsigned char code_uchar;
	
	if(packet_length_uint < 6) return -1;
	code_uchar = packet_uchar[1];
	payloadLength_ushort = (packet_uchar[4] << 8) + packet_uchar[5];
	if(payloadLength_ushort + 6u > packet_length_uint) return -1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<PPPoE Packet>\n");
	*xmlLevel_uint += 1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Version> %hhu </Version>\n", (unsigned char)(packet_uchar[0] >> 4));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Type> %hhu </Type>\n", (unsigned char)(packet_uchar[0] & 0x0F));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Code> %hhu </Code>\n", code_uchar);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Session ID> %hu </Session ID>\n", (unsigned short)((packet_uchar[2] << 8) + packet_uchar[3]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Length> %hu </Length>\n", payloadLength_ushort);
	
	PPP_int(packet_uchar + 6, output_FILE, xmlLevel_uint, payloadLength_ushort);
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</PPPoE Packet>\n");
	return 0;
}