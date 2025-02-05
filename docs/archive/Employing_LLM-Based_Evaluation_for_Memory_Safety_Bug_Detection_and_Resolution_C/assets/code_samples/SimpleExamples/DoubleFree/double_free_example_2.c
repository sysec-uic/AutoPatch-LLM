//https://learn.microsoft.com/en-us/cpp/sanitizers/error-double-free?view=msvc-170
#include <stdlib.h>
#include <string.h>

int main(int c, char** v) {

    char* a = (char*)malloc(10 * sizeof(char));  // Allocate memory
    memset(a, 0, 10);  // Initialize memory to zero
    int r = a[c];  
    free(a);  // Free allocated memory

    
    for (int i = 0; i < c; ++i) {
     
        v[i] = v[i];
    }

    free(a + c - 1);  // Double free
    return r; 
}
