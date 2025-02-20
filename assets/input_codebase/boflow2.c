#include <stdio.h>


// buffer overflow in main
int main() {
    char password[10];
    printf("Enter the password: ");
    gets(password); // Vulnerable: no bounds checking
    if (strcmp(password, "secret") == 0) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }
    return 0;
}
