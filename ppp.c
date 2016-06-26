#include <stdio.h>

#include "indent.h"
#include "ip.h"

int PPP_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint) {
	unsigned short idx_ushort = 0;
	
	if(packet_length_uint < 6) {
		fprintf(output_FILE, "%u/6.\n", packet_length_uint);
		return -1;
	}
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<PPP Packet>\n");
	*xmlLevel_uint += 1;
	
	if(packet_uchar[idx_ushort] == 0x7E) {
		fprintf(output_FILE, "<Flag> 0x7E </Flag>\n");
		idx_ushort = 1;
	}
	else { }//Flag omitted
	
	if(packet_uchar[idx_ushort] != 0xff) { //address omitted
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Control> 0x%02hhX </Control>\n", packet_uchar[idx_ushort]);
		
		idx_ushort += 1;
	}
	else {
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Address> 0xFF </Address>\n");
		
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Control> 0x%02hhX </Control>\n", packet_uchar[idx_ushort + 1]);
		
		idx_ushort += 2;
	}
	
	switch(packet_uchar[idx_ushort]) {
		case 0x21: {
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "<Protocol> 0x0021 </Protocol>\n");
			IP_int(packet_uchar + idx_ushort + 1, output_FILE, xmlLevel_uint, packet_length_uint - idx_ushort - 1);
			break;
		}
		default: {
			Indent_void(output_FILE, *xmlLevel_uint);
			fprintf(output_FILE, "<Data>");
			
			for(; idx_ushort < packet_length_uint; idx_ushort += 1)
				fprintf(output_FILE, "%02hhx ", packet_uchar[idx_ushort]);
			
			fprintf(output_FILE, "</Data>\n");
			break;
		}
	}
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</PPP Packet>\n");
	return 0;
}