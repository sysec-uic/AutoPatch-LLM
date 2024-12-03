#include <stdio.h>

typedef struct {
    char buf2[15];
    char buf[64];
} data_t;


int scramble(int *sequence) {
    data_t data;

    for (int i = 0; i < 5; i++) {
        scanf("%15s", data.buf2);
        strncpy(&data.buf[sequence[i]*15], data.buf2, 15);
        printf(data.buf);
    }
}

void main() {
    int sequence[5] = {3,1,4,0,2};

    scramble(sequence);
}