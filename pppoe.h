#ifndef PPPOE
#define PPPOE

#include <stdio.h>

int PPPOE_Discovery(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length);
int PPPOE_Session(const unsigned char *packet, FILE *output, unsigned int *xmlLevel, unsigned int packet_length);

#endif