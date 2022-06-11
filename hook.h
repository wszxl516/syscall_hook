#ifndef __HOOK__
#define __HOOK__
#include <linux/syscalls.h>
#include <asm/ptrace.h>
#include <linux/kconfig.h>
#include "setpage.h"
#include "symbol.h"
#if defined(CONFIG_X86_64)
    typedef long (*syscall_fn_t)(const struct pt_regs *regs);
#endif
int install_hook(syscall_fn_t *sys_call_table, int syscall_NR, syscall_fn_t hook_fn, syscall_fn_t *org_fn);
int uninstall_hook(syscall_fn_t *sys_call_table, int syscall_NR, syscall_fn_t *org_fn);
#endif
