TARGET1=./bin/echo-server
TARGET2=./bin/echo-client
CPPFLAGS+=-Wall -O2
LDLIBS+=-pthread
#LDLIBS+=-lws2_32 # for mingw

$(CXX)=g++

all: $(TARGET1) $(TARGET2)

$(TARGET1):
	$(CXX) echo-server.cpp $(LOADLIBES) $(LDLIBS) -o $@

$(TARGET2):
	$(CXX) echo-client.cpp $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET1)
	rm -f $(TARGET2)
