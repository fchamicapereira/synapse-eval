SOURCES = $(wildcard *.cpp)
EXECS = $(addprefix build/,$(basename $(SOURCES)))

CC = g++

CFLAGS = -std=c++11
LIBS = -lpcap

release: CFLAGS += -O3
release: all

debug: CFLAGS += -g -O0 -DDEBUG
debug: all

all: $(EXECS)

build/%: %.cpp
	@mkdir -p build
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -rf $(EXECS)
