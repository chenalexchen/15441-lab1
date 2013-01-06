################################################################################
# Makefile                                                                     #
#                                                                              #
# Description: This file contains the make rules for Recitation 1.             #
#                                                                              #
# Authors: Athula Balachandran <abalacha@cs.cmu.edu>,                          #
#          Wolf Richter <wolf@cs.cmu.edu>                                      #
#                                                                              #
################################################################################

CC = gcc
INCLUDE = ./inc


CFLAGS = -Wall -Werror -g -I$(INCLUDE)

LIB = -lssl -lcrypto

# object files needed by server
OBJ = server.o parser.o daemon.o cgi.o






srv: $(OBJ)
	$(CC) $(OBJ) -o srv $(CFLAGS) $(LIB)


%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@



.PHONY: clean veryclean

clean:
	rm srv *.o
veryclean: 
	rm srv *.o *~