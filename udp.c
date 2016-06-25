#include <stdio.h>

#include "indent.h"

int UDP_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint) {
	unsigned short totalLength_ushort, idx_ushort;
	
	totalLength_ushort = (packet_uchar[4] << 8) + packet_uchar[5];
	if(totalLength_ushort < 8 || totalLength_ushort > packet_length_uint) return -1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<UDP Packet>\n");
	*xmlLevel_uint += 1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Src Port> %hu </Src Port>\n", (unsigned short)((packet_uchar[0] << 8) + packet_uchar[1]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Dst Port> %hu </Dst Port>\n", (unsigned short)((packet_uchar[2] << 8) + packet_uchar[3]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Length> %hu </Length>\n", totalLength_ushort);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Checksum> %hu </Checksum>\n", (unsigned short)((packet_uchar[6] << 8) + packet_uchar[7]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Payload Data> ");
	for(idx_ushort = 8; idx_ushort < totalLength_ushort; idx_ushort += 1) {
		fprintf(output_FILE, "%02hhx ", packet_uchar[idx_ushort]);
	}
	fprintf(output_FILE, "</Payload Data>\n");
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</UDP Packet>\n");
	return 0;
}