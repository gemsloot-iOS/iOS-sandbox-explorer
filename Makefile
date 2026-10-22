# Makefile for building DYLIB on macOS/iOS (requires Xcode iphoneos SDK)

CC = clang
IPHONEOS_DEPLOYMENT_TARGET ?= 14.0

# Resolve SDK once; fail fast if xcrun/iphoneos SDK is unavailable
SDKROOT := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
ifeq ($(strip $(SDKROOT)),)
$(error iphoneos SDK not found. Install Xcode (or CLT with iOS SDK) and ensure `xcrun --sdk iphoneos --show-sdk-path` works.)
endif

CFLAGS = -fobjc-arc -framework Foundation -framework Security -dynamiclib -arch arm64 \
	-isysroot $(SDKROOT) -miphoneos-version-min=$(IPHONEOS_DEPLOYMENT_TARGET) -Iinclude
LDFLAGS = -dynamiclib

TARGET = libShell.dylib
SOURCES = src/ShellServer.m src/ShellCommands.m src/main.m
HEADERS = include/ShellServer.h include/ShellCommands.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	rm -f $(TARGET)

.PHONY: all clean
