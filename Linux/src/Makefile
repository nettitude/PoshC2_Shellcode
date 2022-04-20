CC=musl-gcc 

MUSL_INC ?= $(LIB_DIR)musl/include/
CURL_INC ?= $(LIB_DIR)curl/include/
MBED_INC ?= $(LIB_DIR)mbedtls/include/
UZLIB_INC ?= $(LIB_DIR)uzlib/src

CURL_LIB  ?= $(LIB_DIR)curl/lib
MBED_LIB  ?= $(LIB_DIR)mbedtls/lib
UZLIB_LIB ?= $(LIB_DIR)uzlib/lib

OUTPUT_DIR ?=./

CFLAGS := $(CFLAGS) 
CFLAGS += -Wall -Wno-parentheses -O2 -Werror -D_FORTIFY_SOURCE=2
CFLAGS += -I$(MUSL_INC)
CFLAGS += -I$(CURL_INC)
CFLAGS += -I$(MBED_INC)
CFLAGS += -I$(UZLIB_INC)

LIBS := -L$(CURL_LIB) -lcurl
LIBS += -L$(MBED_LIB) -lmbedx509 -lmbedtls -lmbedcrypto
LIBS += -L$(UZLIB_LIB) -ltinf

.PHONY: all
all: TYPE=release
all: clean directories dropper_stripped stage2core

.PHONY: release
release: all

.PHONY: debug
debug: CFLAGS += -DDEBUG -ggdb
debug: TYPE=debug
debug: clean directories dropper stage2core 

dropper_stripped: dropper
	strip $(OUTPUT_DIR)/$(TYPE)/dropper

dropper: dropper.o base64.o common.o 
	$(CC) $(CFLAGS) -Wl,-Tdropper.ld -static dropper.o base64.o common.o $(LIBS) -o $(OUTPUT_DIR)/$(TYPE)/dropper

dropper.o: dropper.c base64.c base64.h common.c common.h
	$(CC) $(CFLAGS) -static -c dropper.c base64.c common.c

stage2core: stage2core.o common.o base64.o
	$(CC) -shared -fPIC stage2core.o base64.o common.o $(LIBS) -o $(OUTPUT_DIR)/$(TYPE)/stage2core.so

stage2core.o: stage2core.c stage2core.h common.h common.c base64.c base64.h
	$(CC) $(CFLAGS) -c -fPIC -fno-stack-protector stage2core.c common.c base64.c

.PHONY: clean
clean:
	rm -rf dropper stage2core.so *.o

.PHONY: directories
directories:
	mkdir -p $(OUTPUT_DIR)/$(TYPE)

