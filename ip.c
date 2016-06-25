#include <stdio.h>
#include <stdlib.h>

#include "indent.h"
#include "tcp.h"
#include "udp.h"

int IP_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint) {
	unsigned short totalLength_ushort, payloadLength_ushort, headerLength_ushort, idx_ushort;
	unsigned char proto_uchar, ihl_uchar;
	//unsigned char cpy_uchar, optNum_uchar, optLen_uchar;
	
	if(packet_length_uint < 20) return -1;
	ihl_uchar = *packet_uchar & 0x0F;
	totalLength_ushort = (packet_uchar[2] << 8) + packet_uchar[3];
	if(totalLength_ushort > packet_length_uint) return -1;
	headerLength_ushort = ihl_uchar << 2;
	if(headerLength_ushort > totalLength_ushort) return -1;
	payloadLength_ushort = totalLength_ushort - headerLength_ushort;
	proto_uchar = packet_uchar[9];
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<IP Packet>\n");
	
	*xmlLevel_uint += 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Version> %hhu </Version>\n", (unsigned char)(*packet_uchar >> 4));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<IHL> %hhu </IHL>\n", ihl_uchar);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<DSCP> %hhu </DSCP>\n", (unsigned char)(packet_uchar[1] >> 2));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<ECN> %hhu </ECN>\n", (unsigned char)(packet_uchar[1] & 0x03));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Total Length> %hu </Total Length>\n", totalLength_ushort);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Identification> %hu </Identification>\n", (unsigned short)((packet_uchar[4] << 8) + packet_uchar[5]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Flags>\n");
	*xmlLevel_uint += 1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<DF> %hhu </DF>\n", (unsigned char)((packet_uchar[6] & 0x40) >> 6));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<MF> %hhu </MF>\n", (unsigned char)((packet_uchar[6] & 0x20) >> 5));
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</Flags>\n");
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<FO> %hu </FO>\n", (unsigned short)(((packet_uchar[6] & 0x1F) << 8) + packet_uchar[7]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<TTL> %hhu </TTL>\n", packet_uchar[8]);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Protocol> %hhu </Protocol>\n", proto_uchar);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Header Checksum> %hu </Header Checksum>\n", (unsigned short)((packet_uchar[10] << 8) + packet_uchar[11]));
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Src IP Addr> %hhu.%hhu.%hhu.%hhu </Src IP Addr>\n", packet_uchar[12], packet_uchar[13], packet_uchar[14], packet_uchar[15]);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Dst IP Addr> %hhu.%hhu.%hhu.%hhu </Dst IP Addr>\n", packet_uchar[16], packet_uchar[17], packet_uchar[18], packet_uchar[19]);
	
	if(headerLength_ushort > 20) {
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Option Data> ");
		for(idx_ushort = 20; idx_ushort < headerLength_ushort; idx_ushort += 1) {
			fprintf(output_FILE, "%02hhx ", packet_uchar[idx_ushort]);
		}
		fprintf(output_FILE, "</Option Data>\n");
	}
	
	switch(proto_uchar) {
		/*case 1: {
			
		}*/
		case 6: {
			TCP_int(packet_uchar + headerLength_ushort, output_FILE, xmlLevel_uint, payloadLength_ushort);
			break;
		}
		
		case 17: {
			UDP_int(packet_uchar + headerLength_ushort, output_FILE, xmlLevel_uint, payloadLength_ushort);
			break;
		}
		default: {
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "<Payload Data> ");
			for(idx_ushort = headerLength_ushort; idx_ushort < totalLength_ushort; idx_ushort += 1) {
				fprintf(output_FILE, "%02hhx ", packet_uchar[idx_ushort]);
			}
			fprintf(output_FILE, "</Payload Data>\n");
		}
	}
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</IP Packet>\n");
	return 0;
}