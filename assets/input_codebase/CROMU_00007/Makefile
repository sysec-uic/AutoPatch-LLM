AUTHOR_ID  = CROMU
SERVICE_ID = 00007
CFLAGS     = -O3 -g -Werror -Wno-overlength-strings -Wno-packed
CC = /home/lleit/cve-sourcing/AFLplusplus/afl-cc


all: compile-gcc run-gcc compile-afl

make-afl: compile-afl

make-gcc: compile-gcc run-gcc

clean:
	rm -f executables/CROMU_00007.afl
	rm -f executables/CROMU_00007
	rm -rf output/

# add flag to makefile
# reset to taking flags for compiler paths, output folder for executables

compile-afl: src/timecard.c src/service.c
	$(AFL_CC_PATH) ${CFLAGS} -o $(AFL_EXEC_PATH) src/timecard.c src/service.c -I ./include

compile-gcc: src/timecard.c src/service.c
	gcc ${CFLAGS} -o executables/CROMU_00007 src/timecard.c src/service.c -I ./include

# takes std in: would need to pipe in the input from the crash detail object by possibly calling the executable 
# in python directly
run-gcc: src/timecard.c src/service.c
	./executables/CROMU_00007
