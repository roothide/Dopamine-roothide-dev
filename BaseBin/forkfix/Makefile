TARGET = forkfix.dylib
CC = clang

CFLAGS = -Werror -dynamiclib -I../_shared -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64e -miphoneos-version-min=15.0 -O2

sign: $(TARGET)
	@ldid -S $^

$(TARGET): $(wildcard src/*.c src/*.S)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)