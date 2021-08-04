#include <stdlib.h>
#include <unistd.h>

void main() {
	char input[16];
	syscall(3, 0, input, 16);
	syscall(0, 0);
}
