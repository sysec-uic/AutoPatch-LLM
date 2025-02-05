#include <stdio.h>
#include <string.h>

const char *PASSWORD_FILE = "cs487";

int main()
{
    char input[8];
    char password[8];

    // Read the password from the PASSWORD_FILE string (simulated here with sscanf)
    sscanf(PASSWORD_FILE, "%s", password);

    // Prompt for the password
    printf("Enter password: ");
    scanf("%s", input);  // Vulnerable to overflow if input exceeds 7 characters

    // Debug prints:
    // printf("Address of input: %p\n", (void *)&input);
    // printf("Address of password: %p\n", (void *)&password);
    // printf("Input: %s\n", input);
    // printf("Password: %s\n", password);

    // Check if the entered password matches
    if (strncmp(password, input, 8) == 0)
        printf("Access granted\n");
    else
        printf("Access denied\n");

    return 0;
}
