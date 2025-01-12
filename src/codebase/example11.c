#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct{
    char name[40];
    char address[60];
    int age;
} person;

void ascii_art(char *filename){
    FILE *file;
    char c;

    file = fopen(filename, "r");
    if (file){
        while ((c = getc(file)) != EOF){
            printf("%c", c);
        }
        fclose(file);
    }
}

void amazing(){
    person p;

    printf("Enter your name: \n");
    scanf("%39s", p.name);

    printf("Enter your address: \n");
    scanf("%59s", p.address);

    if (strlen(p.address) == 59){
        printf("You entered a very long address: ");
        printf(p.address);
        return;
    }

    printf("Enter your age: \n");
    scanf("%d", &p.age);

    printf("Hello %s.\n", p.name);
    printf("You are %d years old.\n", p.age);
    printf("You live at %s.\n", p.address);
}

int main(){
    int choice;

    clearenv();
    ascii_art("banner.txt");
    printf("Welcome to the most amazing program ever!\n");
    amazing();
}