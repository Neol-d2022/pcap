#include <stdio.h>

#include "indent.h"

int TCP_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint) {
	unsigned short headerLength_ushort, payloadLength_ushort, idx_ushort;
	
	if(packet_length_uint < 20) return -1;
	headerLength_ushort = (packet_uchar[12] & 0xF0) >> 2;
	//fprintf(stderr, "%hu / %u\n", headerLength_ushort, packet_length_uint);
	if(headerLength_ushort > packet_length_uint) return -1;
	payloadLength_ushort = packet_length_uint - headerLength_ushort;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<TCP Packet>\n");
	*xmlLevel_uint += 1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Src Port> %hu </Src Port>\n", (unsigned short)((packet_uchar[0] << 8) + packet_uchar[1]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Dst Port> %hu </Dst Port>\n", (unsigned short)((packet_uchar[2] << 8) + packet_uchar[3]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Seq> %hu </Seq>\n", (unsigned int)((packet_uchar[4] << 24) + (packet_uchar[5] << 16) + (packet_uchar[6] << 8) + packet_uchar[7]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Ack> %hu </Ack>\n", (unsigned int)((packet_uchar[8] << 24) + (packet_uchar[9] << 16) + (packet_uchar[10] << 8) + packet_uchar[11]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Data Offset> %hhu </Data Offset>\n", (unsigned char)(headerLength_ushort >> 2));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Flags>\n");
	*xmlLevel_uint += 1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<NS> %hhu </NS>\n", (unsigned char)(packet_uchar[12] & 0x01));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<CWR> %hhu </CWR>\n", (unsigned char)((packet_uchar[13] & 0x80) >> 7));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<ECE> %hhu </ECE>\n", (unsigned char)((packet_uchar[13] & 0x40) >> 6));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<URG> %hhu </URG>\n", (unsigned char)((packet_uchar[13] & 0x20) >> 5));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<ACK> %hhu </ACK>\n", (unsigned char)((packet_uchar[13] & 0x10) >> 4));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<PSH> %hhu </PSH>\n", (unsigned char)((packet_uchar[13] & 0x08) >> 3));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<RST> %hhu </RST>\n", (unsigned char)((packet_uchar[13] & 0x04) >> 2));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<SYN> %hhu </SYN>\n", (unsigned char)((packet_uchar[13] & 0x02) >> 1));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<FIN> %hhu </FIN>\n", (unsigned char)(packet_uchar[13] & 0x01));
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</Flags>\n");
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Windows Size> %hu </Windows Size>\n", (unsigned short)((packet_uchar[14] << 8) + packet_uchar[15]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Checksum> %hu </Checksum>\n", (unsigned short)((packet_uchar[16] << 8) + packet_uchar[17]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Urgent Ptr> %hu </Urgent Ptr>\n", (unsigned short)((packet_uchar[18] << 8) + packet_uchar[19]));
	
	if(headerLength_ushort > 20) {
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Option Data> ");
		for(idx_ushort = 20; idx_ushort < headerLength_ushort; idx_ushort += 1) {
			fprintf(output_FILE, "%02hhx ", packet_uchar[idx_ushort]);
		}
		fprintf(output_FILE, "</Option Data>\n");
	}
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Payload Data> ");
	for(idx_ushort = headerLength_ushort; idx_ushort < packet_length_uint; idx_ushort += 1) {
		fprintf(output_FILE, "%02hhx ", packet_uchar[idx_ushort]);
	}
	fprintf(output_FILE, "</Payload Data>\n");
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</TCP Packet>\n");
	
	return 0;
}