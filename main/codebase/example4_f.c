#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

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
    char buffer[256];
    int fd;

    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("Error opening file");
        return 1;
    }

    read(fd, buffer, sizeof(buffer)-1);
    close(fd);
    
    srand(time(NULL));
    num = atoi(argv[2]);

    data.r = rand();
    strcpy(data.canary,"XXX");
    data.str_p = data.base;

    guess(num, buffer, &data);
}
