#ifndef __KAPI_H__
#define __KAPI_H__
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/binfmts.h>

void dump_strings(const char __user *const __user *strings);
void dump_exec_info(const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp);
#endif //__KAPI_H__