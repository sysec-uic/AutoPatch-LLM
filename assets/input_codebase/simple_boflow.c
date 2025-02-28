#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_SIZE 128

void process_input(char *input) {
    char buffer[MAX_INPUT_SIZE]; 
    strcpy(buffer, input); 

    printf("Processed input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    char input[512];
    fgets(input, sizeof(input), stdin);
    process_input(input);

    return 0;
}
