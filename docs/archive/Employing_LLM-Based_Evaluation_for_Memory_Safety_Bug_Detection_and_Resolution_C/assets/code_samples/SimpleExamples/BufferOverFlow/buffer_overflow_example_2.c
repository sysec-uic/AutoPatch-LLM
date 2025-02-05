#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define BUFSIZE 16  

char *lccopy(const char *str) {
    char buf[BUFSIZE];  // vulnerable buffer
    char *p;

    strcpy(buf, str);  // no bounds checking on input
    for (p = buf; *p; p++) {
        if (isupper(*p)) {
            *p = tolower(*p);  // convert uppercase to lowercase
        }
    }
    return strdup(buf);  // return a duplicate of the modified string
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    char *result = lccopy(argv[1]);
    printf("Modified string: %s\n", result);
    free(result);

    return 0;
}
