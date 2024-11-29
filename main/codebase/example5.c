#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int isAdmin;
    char feedback[32];
    char username[32];
} UserProfile;

void processData(char *name, char *comment) {
    UserProfile profile;
    char feedbackMessage[128];

    profile.isAdmin = 0; // By default, user is not an admin

    strcpy(profile.username, name);
    strcpy(profile.feedback, comment);

    strcpy(feedbackMessage,"Feedback:");
    strcat(feedbackMessage, profile.feedback);

    printf(feedbackMessage);

    if(profile.isAdmin) {
        printf("You have administrative privileges!\n");
        system("/bin/sh"); // Open a shell
    } else {
        printf("You are a regular user.\n");
    }
}

int main() {
    char name[48];
    char comment[48];
    clearenv(); // Clear all environment variables

    printf("Enter your name: ");
    fgets(name, sizeof(name), stdin);

    printf("Any comments? ");
    fgets(comment, sizeof(comment), stdin);

    processData(name, comment);
    return 0;
}