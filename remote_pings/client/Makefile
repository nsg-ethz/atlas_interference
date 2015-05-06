CC = gcc
CFLAGS	= -std=gnu99 -pedantic -Werror -W -Wall -Wextra \
		-Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow \
		-Wbad-function-cast -Wcast-qual -g

client	:	client.o
	$(CC) $(CFLAGS) -o client client.o

client.o	:	client.c
	$(CC) $(CFLAGS) -o client.o -c client.c

clean	:
	rm client client.o


