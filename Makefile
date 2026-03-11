CC = gcc
CFLAGS = -Wall -Werror -g
C_OBJS = packet.o main.o
BUILD = packet-sniffer

all: $(BUILD)

packet.o : packet.h sniffer.h
main.o: packet.h sniffer.h

$(BUILD) : $(C_OBJS)
	$(CC) -o $@ $(CFLAGS) $(C_OBJS)

clean:
	rm $(C_OBJS) $(BUILD)
