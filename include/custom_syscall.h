
#ifndef __CUSTOM_SYSCALL_H__
#define __CUSTOM_SYSCALL_H__
#include <linux/slab.h>
#include <linux/kernel.h>
#include "hook.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    asmlinkage long hook_kill_fn(pid_t pid, int sig);
    asmlinkage long hook_exec_fn(const char __user *filename,
                             const char __user *const argv[],
                             const char __user *const envp[]);
#else
    asmlinkage long hook_exec_fn(const struct pt_regs *regs);
    asmlinkage long hook_kill_fn(const struct pt_regs *regs);
#endif

extern syscall_fn_t     org_sys_execve;
extern syscall_fn_t     org_sys_kill;

#define HOOK_EXECVE     HOOK_DEF("sys_execve", __NR_execve, org_sys_execve, hook_exec_fn)
#define HOOK_KILL       HOOK_DEF("sys_kill", __NR_kill, org_sys_kill, hook_kill_fn)
#endif //__CUSTOM_SYSCALL_H__