#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    FILE *file;
    char filename[36];
    char error_message[36];
    char filecontent[36];
} data_t;

void read_file(char * filename){
    FILE *file;
    char c;

    file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening file.\n");
        return;
    }

    while ((c = getc(file)) != EOF)
        putc(c, stdout);

    fclose(file);
}

void upload_file() {
    data_t data;

    strcpy(data.error_message, "Access denied.\n");

    printf("Enter the filename: ");
    gets(data.filename);

    if (strcmp(data.filename, "secret.txt") != 0) {
        printf(data.error_message);
        exit(-1);
    }
    printf("Enter the file content: ");
    gets(data.filecontent);

    strcpy(data.error_message, "Error opening file.\n");
    data.file = fopen(data.filename, "w");
    if (data.file == NULL) {
        printf(data.error_message);
        return;
    }

    fprintf(data.file, "%s", data.filecontent);
    fclose(data.file);

    printf("File uploaded successfully!\n");
}

int main() {
    int choice;

    printf("You can upload a file and read it again later.\n");
    printf("Choice: ");

    scanf("%d", &choice);
    fflush(stdin);
    if (choice){
        upload_file();
    } else{
        read_file("./secret.txt");
    }

    return 0;
}