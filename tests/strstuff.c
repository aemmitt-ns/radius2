#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(int argc, char** argv) {
	char str[64];
	strcpy(str, argv[1]);
	if (strcmp(str, "p4s5w0rd") == 0) {
		puts("nice one!");
		return 0;
	} else {
		puts("lame one!");
		return 1;
	}
}
