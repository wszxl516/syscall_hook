#ifndef __HOOK__
#define __HOOK__
#include <linux/syscalls.h>
#include <asm/ptrace.h>
#include <linux/kconfig.h>
#include "setpage.h"
#include "symbol.h"
typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);
struct syscall_hook {
    syscall_fn_t custom_syscall;
    syscall_fn_t *org_syscall;
    int syscall_nr;
    char name[128];
};
int install_hook(syscall_fn_t *sys_call_table, struct syscall_hook *hook);
int install_hooks(syscall_fn_t *sys_call_table, struct syscall_hook *hook, int hook_count);
int uninstall_hook(syscall_fn_t *sys_call_table, struct syscall_hook *hook);
int uninstall_hooks(syscall_fn_t *sys_call_table, struct syscall_hook *hook, int hook_count);
#endif
