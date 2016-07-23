#include <stdio.h>
#include <string.h>

#define C_INDENT_STRING "\t"
//#define C_INDENT_STRLEN_LENGTH 2

void Indent(FILE *output, unsigned int indentLevel) {
	unsigned int i;
	for(i = 0; i < indentLevel; i += 1)
		fprintf(output, "%s", C_INDENT_STRING);
}