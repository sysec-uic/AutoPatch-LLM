#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256
#define ALLOC_SIZE 16 // Size of memory to allocate

int main() {
    char input_buffer[BUFFER_SIZE];
    char *data_ptr = NULL;
    int trigger = 0;
    size_t i;

    printf("Input : ");
    fflush(stdout); // Ensure the prompt is displayed before waiting for input

    // Read a line from standard input
    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
        // Handle potential read error or EOF
        if (feof(stdin)) {
            printf("\nEnd of input reached.\n");
        } else {
            perror("Error reading input");
        }
        return 1;
    }

    // Allocate a small block of memory
    data_ptr = (char *)malloc(ALLOC_SIZE);
    if (data_ptr == NULL) {
        perror("Memory allocation failed");
        return 1;
    }
    printf("Memory allocated successfully at address: %p\n", (void *)data_ptr);

    // Scan the input buffer for trigger characters ('$', '3', 'i')
    // These characters have the same single-byte representation in ASCII and UTF-8
    for (i = 0; input_buffer[i] != '\0' && i < BUFFER_SIZE; ++i) {
        if (input_buffer[i] == '$' || input_buffer[i] == '3' || input_buffer[i] == 'i') {
            trigger = 1;
            printf("Trigger character ('%c') found in input.\n", input_buffer[i]);
            break;
        }
    }

    if (trigger) {
        printf("Condition met: Input contains '$', '3', or 'i'.\n");

        free(data_ptr);
        printf("First free call completed.\n");

        free(data_ptr);

    } else {
        printf("Condition not met: Input does not contain '$', '3', or 'i'.\n");
        free(data_ptr);
        printf("Memory freed successfully.\n");
    }

    data_ptr = NULL;
    return 0;
}