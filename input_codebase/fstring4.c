#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef struct {
    char username[40];
    char password[20];
    char secret[20];
    int randomFd;
} user_t;

void welcome_user(user_t * user){
    char message[52];
    strcpy(message, "Ciao to "); // len 8
    strcat(message, user->username); // len 8+40
    strcat(message, "\n"); // len 8+40+1 == 49 < 52, ok
    printf(message);
    return;
}

int main() {
    user_t user;

    printf("Insert your name: ");
    fflush(stdout);
    read(0, &user.username, 40); // 0 == stdin
    printf("Insert your password: ");
    fflush(stdout);
    read(0, &user.password, 20); // 0 == stdin

    user.randomFd = open("/dev/urandom", O_RDONLY);
    read(user.randomFd, &user.secret, 20);

    welcome_user(&user);
    if (!strncmp(user.password, user.secret, 20)){
        printf("You're a lucky user!\n");
        system("/bin/sh");
    }else{
        printf("The Mirage Island isn't visible today :(\n");
    }

    return 0;
}