
CC = gcc
FLAGS = -Wall -g
DEBUG_FLAGS = -DDEBUG

filesafe: filesafe.c
	$(CC) $(FLAGS) -o filesafe filesafe.c

debug: filesafe.c
	$(CC) $(FLAGS) $(DEBUG_FLAGS) -o filesafe filesafe.c

clean:
	rm -f filesafe
