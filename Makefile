CFLAGS=-O2 -std=c99 -Wall
OPTFLAGS=-s 
LDFLAGS=

all:
	gcc $(CFLAGS) $(OPTFLAGS) -o proxy_diskbuffer proxy_diskbuffer.c $(LDFLAGS)
darwin:
	gcc $(CFLAGS) -o proxy_diskbuffer proxy_diskbuffer.c $(LDFLAGS)
clean:
	rm -f proxy_diskbuffer proxy_diskbuffer.exe
