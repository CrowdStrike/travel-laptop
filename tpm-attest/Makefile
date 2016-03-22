CXX?=g++
CFLAGS+=-O3 -ggdb
LDFLAGS+=-ltspi -lcrypto -ljsoncpp

.PHONY: all clean

all: quote-make quote-verify

quote-make: quote-make.o base64.o
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

quote-verify: quote-verify.o base64.o
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CFLAGS) -c -o $@ $<


clean:
	rm -f *.o quote-verify quote-make
