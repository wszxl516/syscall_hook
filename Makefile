MODULE_NAME=test
KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build
ccflags-y := -g -DDEBUG
$(MODULE_NAME)-objs := main.o hook.o setpage.o symbol.o
obj-m := $(MODULE_NAME).o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
