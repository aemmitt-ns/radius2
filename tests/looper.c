#include<stdio.h>

int main() {
	int x = 1;
	for(int i=0; i < 0x100000; i++) {
		x += i;
		if (x > 0x1337) {
			x -= 0x1337;
		}
	}
	return x;
}
