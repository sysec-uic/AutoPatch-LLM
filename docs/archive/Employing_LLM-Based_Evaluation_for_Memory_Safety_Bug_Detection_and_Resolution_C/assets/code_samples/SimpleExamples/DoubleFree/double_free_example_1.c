//https://learn.microsoft.com/en-us/cpp/sanitizers/error-double-free?view=msvc-170

#include <stdio.h>
#include <stdlib.h>

void processArray(int *arr) {
    for (int i = 0; i < 42; ++i) {
        arr[i] = i * 2;
    }
}

int main() {
    int *x = (int *)malloc(42 * sizeof(int));  // Allocate memory for an array of 42 integers

    processArray(x);

    // Free the allocated memory
    free(x);

    printf("Hello World, no vulnerabilities here\n");

    // Free memory again (intentional double-free vulnerability)
    free(x);

    return 0;
}
