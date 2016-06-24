#include <stdio.h>
#include <string.h>

#define C_INDENT_STRING "\t"
//#define C_INDENT_STRLEN_LENGTH 2

void Indent_void(FILE *output_FILE, unsigned int indentLevel_uint) {
	unsigned int i_uint;
	for(i_uint = 0; i_uint < indentLevel_uint; i_uint += 1)
		fprintf(output_FILE, "%s", C_INDENT_STRING);
}