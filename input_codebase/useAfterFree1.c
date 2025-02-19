#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function() {
    char *data = (char *)malloc(16);
    if (data == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    strcpy(data, "Hello, World!");
    printf("Data: %s\n", data);

    free(data);

    printf("Accessing freed memory: %s\n", data);

    char *new_data = (char *)malloc(16);
    strcpy(new_data, "Exploited!");
    printf("New data: %s\n", new_data);
}

int main() {
    vulnerable_function();
    return 0;
}