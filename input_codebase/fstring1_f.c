#include <stdio.h>

int main(int argc, char **argv) {
    char str[128];
    char *secret = "This is a secret!\n";

    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    if (fgets(str, sizeof(str), file) == NULL) {
        printf("Error reading from file or file is empty.\n");
        fclose(file);
        return 1;
    }

    printf(str);
    fclose(file);

    return 0;
}
