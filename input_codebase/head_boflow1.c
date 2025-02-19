#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(const char *input) {
    // Allocate a small buffer on the heap
    char *heap_buffer = (char *)malloc(16);
    if (heap_buffer == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    printf("Allocated 16 bytes on the heap.\n");

    // Unsafe copy: Does not check the length of the input
    strcpy(heap_buffer, input);

    printf("Buffer content: %s\n", heap_buffer);

    // Clean up
    free(heap_buffer);
}

int main() {
    char input[100];

    scanf("%s", input);

    vulnerable_function(input);

    return 0;
}
