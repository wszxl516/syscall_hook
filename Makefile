NAME=test
ifneq ($(KERNELRELEASE),)
	SRCS := $(shell find ${M}/src -name "*.c")
	INCLUDE := $(foreach dir, $(shell find ${M}/include -type  d), -I$(dir))
	OBJS := $(SRCS:$(M)/%.c=%.o)
	EXTRA_CFLAGS := -w -g $(INCLUDE) $(KERNEL_CFLAGS) -D __GIT_VERSION__=$(GIT_VERSION)
	$(NAME)-objs := $(OBJS)
	obj-m = $(NAME).o

else
	PWD := $(shell pwd)
	GIT_VERSION = $(shell git rev-parse --short HEAD)
	KDIR:= /lib/modules/`uname -r`/build GIT_VERSION='0x0$(GIT_VERSION)'

all:
	make -C $(KDIR) M=$(PWD)
	@mv $(NAME).ko $(NAME).ko.unstripped
	@strip --strip-debug $(NAME).ko.unstripped -o $(NAME).ko

clean:
	@find . -name "*.cmd" \
			-or -name "*.cmd.*" \
			-or -name "*.o" \
			-or -name ".*.cmd" \
			-or -name "*.o.d" \
			|xargs -i rm "{}"
	@rm -rf .depend *.ko *.ko.* *.mod *.mod.c .tmp_versions .*.o.d Module.symvers modules.order
endif
