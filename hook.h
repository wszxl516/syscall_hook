#ifndef __HOOK__
#define __HOOK__
#include "setpage.h"
#include "symbol.h"
#include <asm/ptrace.h>
#include <linux/kconfig.h>
#include <linux/syscalls.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
typedef unsigned long syscall_fn_t;
typedef asmlinkage long (*sys_kill_fn)(pid_t pid, int sig);
typedef asmlinkage long (*sys_execve_fn)(const char *filename,
                                         const char *const argv[],
                                         const char *const envp[]);
#else
typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);
#endif
struct syscall_hook {
  syscall_fn_t custom_syscall;
  syscall_fn_t *org_syscall;
  int syscall_nr;
  char name[128];
};

#define HOOK(_name, _nr, _org, _custom)                                        \
  {                                                                            \
    .custom_syscall = (syscall_fn_t)_custom, .org_syscall = &_org,             \
    .syscall_nr = _nr, .name = (_name)                                         \
  }
int install_hook(syscall_fn_t *sys_call_table, struct syscall_hook *hook);
int install_hooks(syscall_fn_t *sys_call_table, struct syscall_hook *hook,
                  int hook_count);
int uninstall_hook(syscall_fn_t *sys_call_table, struct syscall_hook *hook);
int uninstall_hooks(syscall_fn_t *sys_call_table, struct syscall_hook *hook,
                    int hook_count);
#endif
