#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void process_file(const char *filename) {
    char line[50];
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    while (fgets(line, 200, file)) { // Vulnerable: buffer size mismatch
        printf("Read line: %s", line);
    }

    fclose(file);
}

int main() {
    char filename[30];
    printf("Enter filename: ");
    gets(filename); // Vulnerable: no bounds checking
    process_file(filename);
    return 0;
}
