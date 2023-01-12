.PHONY = all clean
#Defining Macros
AR = ar
CC = gcc
FLAGS = -Wall -g

all: Sniffer

#Creating Programs
Sniffer: Sniffer.c
	$(CC) $(FLAGS) Sniffer.c -o sniffer

clean:
	rm -f sniffer