#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct{
    char name[4];
    char description[36];
    int hack_index;
} hackemon;

void add_hackemon(){
    hackemon h;

    h.hack_index = 1;

    while (h.hack_index > 0){
        strcpy(h.description, "hakachu is the best hackémon");

        puts("Enter the hackémon name:");
        scanf("%112s", h.name);

        puts("New hackémon added!");
        printf(h.description);

        h.hack_index--;
    }
}

int main(){
    clearenv();
    add_hackemon();
    return 0;
}