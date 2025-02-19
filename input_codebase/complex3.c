#include <stdio.h>
 
int main(int argc, char **argv) {
    char str[128];
    char *secret = "This is a secret!\n";
 
    printf("Enter a string: ");
    scanf("%s", str);
    
    printf(str);
 
    return 0;
}