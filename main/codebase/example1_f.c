#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    char name[64];
    FILE *file;

    if (argc != 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    if (fscanf(file, "%s", name) != 1) {
        printf("Error reading name from file.\n");
        fclose(file);
        return 1;
    }

    fclose(file);
    printf("Welcome, %s!\n", name);
    return 0;
}
