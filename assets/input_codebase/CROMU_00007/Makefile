CFLAGS     = -O3 -g -Werror -Wno-overlength-strings -Wno-packed -fsanitize=address -m32

clean:
	rm -f executables/CROMU_00007.afl
	rm -f executables/CROMU_00007
	rm -rf output/


compile: src/timecard.c src/service.c
	$(CC_PATH) ${CFLAGS} -o $(EXEC_PATH) src/timecard.c src/service.c -I ./include
