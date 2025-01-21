#include <stdio.h>

int main(int argc, char* argv[]) {
	char name[64];

	printf("Enter your name: ");
	scanf("%s", name);
	printf("Welcome, %s!", name);
	return 0;
}
