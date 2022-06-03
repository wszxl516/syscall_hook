#ifndef __SYMBOL_FIND__
#define __SYMBOL_FIND__
#include <linux/kprobes.h>
unsigned long lookup_name(const char *name);
#endif