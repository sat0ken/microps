APPS = 

DRIVERS = driver/dummy.o \
		  driver/loopback.o \

OBJS = util.o \
       net.o \
       ether.o \
       arp.o \
       ip.o \
       icmp.o \

TESTS = test/step16.exe \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -iquote .

ifeq ($(shell uname),Linux)
  # Linux specific settings
  BASE = platform/linux
  CFLAGS := $(CFLAGS) -pthread -iquote $(BASE)
  DRIVERS := $(DRIVERS) $(BASE)/driver/ether_tap.o
  OBJS := $(OBJS) $(BASE)/intr.o
endif

ifeq ($(shell uname),Darwin)
  # macOS specific settings
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)

rm:
	rm -f ./test/*.exe -f ./test/*.o

tap:
	sudo ip tuntap add mode tap user $(USER) name tap0
	sudo ip addr add 192.0.2.1/24 dev tap0
	sudo ip link set tap0 up