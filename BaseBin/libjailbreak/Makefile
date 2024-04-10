TARGET = libjailbreak.dylib

CC = clang

CFLAGS = -Werror -framework Foundation -framework CoreServices -framework Security -framework IOKit -I../_shared -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -Wno-nullability-completeness-on-arrays -dynamiclib -install_name @loader_path/$(TARGET) -O3
LDFLAGS = -lbsm -L../libfilecom -lfilecom -L../ChOma/output/ios/lib/ -lchoma

sign: $(TARGET)
	@ldid -S $<

$(TARGET): $(wildcard src/*.m src/*.c src/*.S)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)