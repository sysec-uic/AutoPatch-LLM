#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char username[32];
    char secret[8];
    char msg1[16];
    char *msg;
    char token[16];
} UserData;

int read_file(char *filename, UserData *data) {
    FILE *file = fopen(filename, "r");
    fscanf(file, "%7s", data->secret);
    fclose(file);
    printf(data->username);
    return 0;
}

void guess_token(UserData *data) {
    char guess[16];

    scanf("%15s", guess);
    if (strcmp(data->token, guess) == 0) {
        system("/bin/sh");
    } else {
        printf("Incorrect token\n");
    }
}

int main() {
    UserData data = { .msg1 = "Token generated" }; // Initialize msg1
    clearenv(); // Clear environment variables

    scanf("%31s", data.username);
    read_file("/etc/secret", &data);
    strcpy(data.token, data.secret);
    strcat(data.token, data.username);
    data.msg = data.msg1;
    printf("%s\n", data.msg);
    guess_token(&data);
    return 0;
}