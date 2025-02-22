## Troubleshooting for afl service!

### Recognizing Issues
Some issues will be noticed when running the main.py script when prompted with this error message:

    [Errno 2] No such file or directory: 'output_vulnerable/crashes/'
    No output crashes folder found. It is likely that the fuzz command did not execute correctly. Please go to docs/afl_troubleshooting.txt for help.

Other issues may be clear if the program (specifically the fuzzer part) run for a much shorter amount of time than indicated in the timeout. This 
is often accompanied by the fuzzer saying that it found no crashes. In either of these cases as well as when you recieve the no output folder error 
message, proceed with the following:

### Step 1: compile the program in the command line.
To diagnose the issue, go to the command_log directory, find the file for the program target, and first try running the fuzzer compile command.


#### 1. if output = 
    zsh: no such file or directory: ../afl-2.52b/afl-gcc
This indicates that you have not set up afl. Please go to the afl-2.52b directory and run make. If you experience any build issues, refer to their 
documentation. When you run make, you will see an output line that looks like this: 

    unset AFL_USE_ASAN AFL_USE_MSAN; AFL_QUIET=1 AFL_INST_RATIO=100 AFL_PATH=. ./afl-gcc -O3 .....

The text following AFL_PATH indicates the compiler that afl has chosen based on your system. Ensure that the AFL_COMPILER_PATH environment variable is set to the absolute path to this file.

#### 2. if output =
    [-] PROGRAM ABORT : Incorrect use (not called through afl-gcc?)
This indicates that there is a mismatch in the compiler path listed in the top of main.py vs. the compiler that afl has 
chosen based on your system. Perform make clean in the afl folder and go to option 1 to see the correct compiler to use, and update the AFL_COMPILER_PATH environment variable.
 
#### 3. nothing out of the ordinary happens/you get the normal message indicating any warnings.
If this happens, proceed to the next step.

### Step 2: run the fuzzer in the command line.

The following things might happen:

#### 1. if you get a message that looks something like this:
    "Hmm, your system is configured to send core dump notifications to an external utility. 
    This will cause issues: there will be an extended delay between stumbling upon a crash and having this information 
    relayed to the fuzzer via the standard waitpid() API...."

I get this when working on a google cloud instance.
Either perform the fix it directs (which might be dangerous), or you can export the environment variable AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES by 
executing 

    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 

in the command line or adding it to the 
devcontainer.env. The second solution is not ideal, but is fine for 
a temporary fix for testing purposes/getting acquainted with the service.

#### 2. if you get a message that looks something like this:

    [-] Uh-oh, looks like all 2 CPU cores on your system are allocated to
    other instances of afl-fuzz (or similar CPU-locked tasks). Starting
    another fuzzer on this machine is probably a bad plan, but if you are
    absolutely sure, you can set AFL_NO_AFFINITY and try again.

    [-] PROGRAM ABORT : No more free CPU cores
         Location : bind_to_free_cpu(), afl-fuzz.c:490\

This indicates that you are experiencing the bug in which the fuzzer process continues after the service finishes 
executing. To work around this, remove the output_* folders in between runs, this will stop the execution of afl in 
the background. This bug will be fixed shortly in another PR.

#### 3. any other common error messages and solutions can be put here.

NOTE: it's important to run the rm-temp-dirs task from the taskfile in between runs. If you don't remove the output directories from a 
particular run, you could have issues with the fuzzer that you don't notice. Eventually error detection in afl will be automatically noticed/handled.