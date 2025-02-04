This folder and subfolder is to be used as a workspace to organize system and user prompts.

Update this README with a HUMAN readable version of each system-user-prompt combination.  Use individual files for MACHINE readable versions.  Use the `data/` folder to organize LLM responses.

An example of a system prompt:

"You are a helpful AI assistant familiar with the C programming language, cybersecurity and low level memory safety bugs.  Construct your answers using concise language, and do not add additional data or make up answers."


An example of a user prompt:

"Read the following C code delimited by triple backticks, and add a line printing the value of the summation of 3 and 4.

```
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```
"