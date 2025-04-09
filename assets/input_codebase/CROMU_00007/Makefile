CFLAGS     = -O3 -g -Werror -Wno-overlength-strings -Wno-packed

clean:
	rm -f executables/CROMU_00007.afl
	rm -f executables/CROMU_00007
	rm -rf output/


compile-afl: src/timecard.c src/service.c
	$(AFL_CC_PATH) ${CFLAGS} -o $(AFL_EXEC_PATH) src/timecard.c src/service.c -I ./include

compile-gcc: src/timecard.c src/service.c
	$(GCC_PATH) ${CFLAGS} -o $(GCC_EXEC_PATH) src/timecard.c src/service.c -I ./include


