#include <stdio.h>
#include <string.h>

// buffer overflow in a helper function
void get_input() {
    int number = 3000;
    char buffer[20];
    printf("Enter your name: ");
    gets(buffer); // Vulnerable: no bounds checking
    char * heapAlloc = (char *) malloc(sizeof(char) * 2);
    *heapAlloc = number;
    if (number != 3000) {
        free(heapAlloc);
        heapAlloc = NULL;
    }
    printf("This is my favorite number: %d", number);

    printf("Hello, %s!\n", buffer);
}

int main() {
    get_input();
    return 0;
}
