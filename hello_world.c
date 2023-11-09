#include <stdio.h>
#include <stdlib.h>

int main() {
	char msg[10000];
	fgets(msg, 1000, stdin);

	printf("Your message: %s", msg);
	return 0;
}