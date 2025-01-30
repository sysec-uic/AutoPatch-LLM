# Intro to AutoPatch Service!

## Motivation
Finding bugs in systems code is very time consuming. Up until now, the method has been to find these bugs through human reads of code/the response to crashes that occur because of these bugs. 

How can we automate bug finding? How can we automate bug fixes, and test the efficacy of these fixes?

## Bugs of Interest
The most crucial bugs to find are memory safety bugs. These occur when memory that should be off-limits (or out of bounds) to a certain program or user are accessed-- either read or written to.

Examples:
- buffer overflow: https://www.geeksforgeeks.org/buffer-overflow-attack-with-example/
- print format vulnerability: https://www.geeksforgeeks.org/format-string-vulnerability-and-prevention-with-example/
- use after free
- integer overflow: https://www.geeksforgeeks.org/check-for-integer-overflow/



## What is Fuzzing?
A way to automatically find crashes in a program that takes either user input from stdin or a file.
We need:
- some initial input
- some program file (can be a wide variety of languages)

The fuzzer: 
- mutates that input to try to find all the branches of the program 
- logs crashes and hangs

Small example: say we have the code below and initial input of "h e i"

    if input == hello: // this is a branch
        .. some code ..

        if input2 == hey: // this is a branch
            ** crash code **

    if input == hi: // this is a branch
        ** crash code **

    .. some code .. // this is a branch


## Basics of the Service:

#### 1. take a buggy source file
#### 2. compile it using an address sanitizer -> basically just notes any warnings and logs them
#### 3. compile program into afl executable 
#### 4. fuzz the program to find crashes 
#### 5. take all the above info + source code text and ask gpt4: hey, can you patch this?
#### 6. test patch by repeating above steps

In the future, we want to separate the fuzzing, static analysis, patching, and evaluation services.

## Demo!
### Prerequisites
main.py, demo, demo_input

OpenAI API key exported as the environment variable OPEN_API_KEY.


Don't have an open ai api key? ask chatGPT this: 

    Q) how do I get an open ai api key and put money on it to use the api for gpt4?

And finally afl-2.52b: https://lcamtuf.coredump.cx/afl/

### The vulnerable code: vulnerable.c

The program takes in user input to perform some simple commands.
Commands:

    u <N> <string> =  Uppercased version of the first <N> bytes of <string>

    head <N> <string> = The first <N> bytes of <string>
Hidden easter egg command not released to user:

    surprise! = *(char *)1 = 2; //attempted write to invalid memory address

This is a good example for fuzzing because there are many control flow paths to find, multiple opportunities for bugs 
with inputs ranging from specific to generic.

### Running the demo
Simply configure your developer environment, and run python main.py in the src directory. 

Watch the following directories be made:
- command log: where you can find the commands that the service ran, so you can debug/learn how to run afl outside of the service.
- bug logs: where the warnings/output from compilation go.
- output_vulnerable: where the fuzzer does all the work.
- patched_codes: where the patched codes go.

### Interpreting the output
The fuzzer generates output folders for each file that it fuzzes. Each output folder contains:
- crashes: the inputs that cause crashes, indexed, and listed by crash type.
- hangs: the inputs that cause hangs, indexed.
- .curr_input: what the fuzzer is putting into the program right now.
- the stats files: where you can keep track of the fuzzer progress on a larger scale. 

### Having Trouble?
Refer to the afl_troubleshooting.md file!


