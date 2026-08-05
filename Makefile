CC=gcc
CFLAGS=-Iinclude -MD -MP
SOURCES=$(wildcard src/*.c)
OBJECTS=$(SOURCES:src/%.c=build/%.o)
DEPENDS=$(SOURCES:src/%.c=build/%.d)
PROGRAM=wifilocator

all:$(PROGRAM)

$(PROGRAM):$(OBJECTS)
	$(CC) -o $@ $^

build:
	mkdir -p build

-include $(DEPENDS)
build/%.o:src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f wifilocator
	rm -rf build/*.d build/*.o
	rmdir build/
