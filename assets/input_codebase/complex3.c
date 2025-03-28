#include <stdio.h>
 
int main(void) {
    char str[128];
    char *secret = "This is a secret!\n";  // still declared but not used

    /* Read a line from stdin.
       This will work when input is redirected from a file or piped from another command. */
    if (fgets(str, sizeof(str), stdin) != NULL) {
        printf("%s", str);
    }
    
    return 0;
}
