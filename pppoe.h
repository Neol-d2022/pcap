#ifndef PPPOE
#define PPPOE

#include <stdio.h>

int PPPOE_Discovery_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint);
int PPPOE_Session_int(const unsigned char *packet_uchar, FILE *output_FILE, unsigned int *xmlLevel_uint, unsigned int packet_length_uint);

#endif