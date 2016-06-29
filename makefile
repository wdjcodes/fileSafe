
CC = gcc
FLAGS = -Wall -g
DEBUG_FLAGS = -DDEBUG
EXE = -o filesafe.out
filesafe: filesafe.c
	$(CC) $(FLAGS) $(EXE) filesafe.c

debug: filesafe.c
	$(CC) $(FLAGS) $(DEBUG_FLAGS) $(EXE) filesafe.c

clean:
	rm -f filesafe.out
