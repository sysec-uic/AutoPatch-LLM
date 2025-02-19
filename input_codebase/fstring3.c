#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct {
    int ch;
    int index;
    FILE *f;
    char file_content[64];
} foo;

void open_whatever(char *filename){
    foo p;

    // Open the file
    p.f = fopen(filename,"r");
    if (p.f == NULL){
        puts("The file is missing.");
        exit(1);
    }

    // Put the file in file content until a newline character is found
    p.index = 0;
    while ((p.ch = fgetc(p.f)) != '\n'){
        if (p.ch == EOF){
            break;
        }
        p.file_content[p.index] = p.ch;
        p.index++;
    }
    p.file_content[p.index] = '\0';
    fclose(p.f); // close the file

    // Compare the first 4 chars of the file with "flag"
    if (strncmp(p.file_content, "flag", 4) == 0){
    printf(p.file_content);
    }
}

void write_whatever(char *filename){
    FILE *f = fopen(filename,"w");
    if (f == NULL){
        puts("The file is missing.");
        exit(1);
    }

    printf("Write something to the file: ");

    // Write from stdin to the file until a newline character is found
    int ch;
    while ((ch = getchar()) != '\n') {
        fputc(ch, f);
    }
    fclose(f); // close the file
}

int main(){
    char filename[12] = "file.txt";
    clearenv();
    write_whatever(filename);
    open_whatever(filename);
}