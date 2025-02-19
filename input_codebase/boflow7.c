#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char base[8];
    int r;
    char buf[64];
    char *str_p;
    char canary[4];
} data_t;

void guess(int num, char *str, data_t *data) {
    snprintf(data->buf, num, str);

    if (strncmp(data->buf,"backdoor",8) == 0) {
        scanf("%8s", data->str_p);

        if (num == data->r){
            system("/bin/sh\0");
        }
    }
    if (strcmp(data->canary, "XXX") != 0)
        abort();
}

int main(int argc, char** argv) {
    int num;
    data_t data;

    num = 10;

    srand(time(NULL));
    data.r = rand();
    strcpy(data.canary,"XXX");
    data.str_p = data.base;

    char *str;
    scanf("%s", str);

    guess(atoi(argv[1]), argv[2], &data);
}
