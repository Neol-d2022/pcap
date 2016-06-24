#include <stdio.h>

#include "indent.h"
#include "ip.h"

int Ethernet_int(const unsigned char *frame_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int frame_length_uint) {
	unsigned int frameIdx_uint, upper_uint;
	unsigned short eType_ushort;
	
	if(frame_length_uint < 64) return -1;
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Ethernet Frame>\n");
	
	*xmlLevel_uint += 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Destination MAC> %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX </Destination MAC>\n", frame_uchar[0], frame_uchar[1], frame_uchar[2], frame_uchar[3], frame_uchar[4], frame_uchar[5]);
	
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "<Source MAC> %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX </Source MAC>\n", frame_uchar[6], frame_uchar[7], frame_uchar[8], frame_uchar[9], frame_uchar[10], frame_uchar[11]);
	
	eType_ushort = (frame_uchar[12] << 8) + frame_uchar[13];
	if(eType_ushort >= 0x0800) {
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<EtherType> 0x%04hX </EtherType>\n", eType_ushort);
		
		switch(eType_ushort) {
			case 0x0800: {
				IP_int(frame_uchar + 14, output_FILE, xmlLevel_uint, frame_length_uint - 14);
				break;
			}
			/*case 0x0806: {
				break;
			}
			case 0x8137: {
				break;
			}
			case 0x8863: {
				break;
			}
			case 0x8864: {
				break;
			}*/
			default: {
				/*Indent_void(output_FILE, *xmlLevel_uint);
				fprintf(output_FILE, "<Payload> ");
				
				upper_uint = frame_length_uint - 2;
				for(frameIdx_uint = 14; frameIdx_uint < upper_uint; frameIdx_uint += 1)
					fprintf(output_FILE, "%02hhx ", frame_uchar[frameIdx_uint]);
				fprintf(output_FILE, "</Payload>\n");*/
				break;
			}
		}
	}
	else {
		Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Length> 0x%02hX <Length>\n", eType_ushort);
		
		/*Indent_void(output_FILE, *xmlLevel_uint);
		fprintf(output_FILE, "<Payload> ");
		
		upper_uint = frame_length_uint - 2;
		for(frameIdx_uint = 14; frameIdx_uint < upper_uint; frameIdx_uint += 1)
			fprintf(output_FILE, "%02hhx ", frame_uchar[frameIdx_uint]);
		fprintf(output_FILE, "</Payload>\n");*/
	}
	
	*xmlLevel_uint -= 1;
	Indent_void(output_FILE, *xmlLevel_uint);
	fprintf(output_FILE, "</Ethernet Frame>\n");
	return 0;
}