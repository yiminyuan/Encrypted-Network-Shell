CFLAGS=-Wall -pthread -lmcrypt -O2

all: client.c server.c
	@ gcc $(CFLAGS) client.c -o client
	@ gcc $(CFLAGS) server.c -o server

clean:
	@ rm -f client server
