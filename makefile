.PHONY = all clean
#Defining Macros
AR = ar
CC = gcc
FLAGS = -Wall -g

all: Sniffer Spoofer Snoofer

#Creating Programs
Sniffer: Sniffer.c
	$(CC) $(FLAGS) Sniffer.c -o sniffer -lpcap

Spoofer: Spoofer.c
	$(CC) $(FLAGS) Spoofer.c -o spoofer

Snoofer: Snoofer.c
	$(CC) $(FLAGS) Snoofer.c -o snoofer -lpcap

clean:
	rm -f sniffer spoofer snoofer