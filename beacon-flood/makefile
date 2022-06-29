CXX=g++
CFLAGS=-lpcap
#CFLAGS=-lm -lpthread

all: beacon-flood

beacon-flood:
	$(CXX) -o beacon-flood beacon-flood.cpp $(CFLAGS)

clean:
	rm -f beacon-flood