MODULE_NAME=test
ARCH ?=
ifeq ($(ARCH),arm64)
	KERNEL_PATH=/data/linux
	CC=clang 
	ARCH=arm64
	CROSS_COMPILE=aarch64-linux-gnu-
else
	KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build
	CC=gcc 
	ARCH=x86_64
	CROSS_COMPILE=

endif
ccflags-y := -g -DDEBUG
$(MODULE_NAME)-objs := main.o hook.o setpage.o symbol.o
obj-m := $(MODULE_NAME).o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules ARCH="$(ARCH)" CC="$(CC)" CROSS_COMPILE="$(CROSS_COMPILE)"

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean ARCH="$(ARCH)" CC="$(CC)"  CROSS_COMPILE="$(CROSS_COMPILE)"

