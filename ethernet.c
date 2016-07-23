#include <stdio.h>

#include "indent.h"
#include "pppoe.h"
#include "ip.h"

int Ethernet(const unsigned char *frame, FILE *output, unsigned int *xmlLevel, unsigned int frame_length) {
	unsigned int frameIdx, upper;
	unsigned short eType;
	
	if(frame_length < 64) return -1;
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Ethernet Frame>\n");
	
	*xmlLevel += 1;
	Indent(output, *xmlLevel);
	fprintf(output, "<Destination MAC> %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX </Destination MAC>\n", frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]);
	
	Indent(output, *xmlLevel);
	fprintf(output, "<Source MAC> %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX </Source MAC>\n", frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]);
	
	eType = (frame[12] << 8) + frame[13];
	if(eType >= 0x0800) {
		Indent(output, *xmlLevel);
		fprintf(output, "<EtherType> 0x%04hX </EtherType>\n", eType);
		
		switch(eType) {
			case 0x0800: {
				IP(frame + 14, output, xmlLevel, frame_length - 14);
				break;
			}
			/*case 0x0806: {
				break;
			}
			case 0x8137: {
				break;
			}*/
			case 0x8863: {
				PPPOE_Discovery(frame + 14, output, xmlLevel, frame_length - 14);
				break;
			}
			case 0x8864: {
				PPPOE_Session(frame + 14, output, xmlLevel, frame_length - 14);
				break;
			}
			default: {
				Indent(output, *xmlLevel);
				fprintf(output, "<Payload> ");
				
				upper = frame_length - 2;
				for(frameIdx = 14; frameIdx < upper; frameIdx += 1)
					fprintf(output, "%02hhx ", frame[frameIdx]);
				fprintf(output, "</Payload>\n");
				break;
			}
		}
	}
	else {
		Indent(output, *xmlLevel);
		fprintf(output, "<Length> 0x%02hX <Length>\n", eType);
		
		Indent(output, *xmlLevel);
		fprintf(output, "<Payload> ");
		
		upper = frame_length - 2;
		for(frameIdx = 14; frameIdx < upper; frameIdx += 1)
			fprintf(output, "%02hhx ", frame[frameIdx]);
		fprintf(output, "</Payload>\n");
	}
	
	*xmlLevel -= 1;
	Indent(output, *xmlLevel);
	fprintf(output, "</Ethernet Frame>\n");
	return 0;
}