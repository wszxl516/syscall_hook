#include "hook.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static syscall_fn_t *syscall_table;
static syscall_fn_t original_kill = (syscall_fn_t)NULL;
static syscall_fn_t original_execve = (syscall_fn_t)NULL;

#if !defined(CONFIG_X86_64) && !defined(CONFIG_ARM64)
#error Currently only x86_64 and arm64 architecture is supported
#endif

MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Syscall hook on linux");
MODULE_AUTHOR("sun");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
asmlinkage long hook_kill_fn(pid_t pid, int sig) {
  struct task_struct *taskp;
  struct pid *s_pid;
  s_pid = find_get_pid(pid);
  if (s_pid != NULL) {
    taskp = get_pid_task(s_pid, PIDTYPE_PID);
    pr_info("send signal %d to pid: %d name : %s\n", sig, pid, taskp->comm);
  } else {
    pr_info("pid %d does not exists!\n", pid);
  }

  return ((sys_kill_fn)(original_kill))(pid, sig);
}
#else
asmlinkage long hook_kill_fn(const struct pt_regs *regs) {
  struct task_struct *taskp;
  pid_t pid, sig;
  struct pid *s_pid;
#if defined(CONFIG_ARM64)
  pid = regs->regs[0];
  sig = regs->regs[1];
#endif
#if defined(CONFIG_X86_64)
  pid = regs->di;
  sig = regs->si;
#endif
  s_pid = find_get_pid(pid);
  if (s_pid != NULL) {
    taskp = get_pid_task(s_pid, PIDTYPE_PID);
    pr_info("send signal %d to pid: %d name : %s\n", sig, pid, taskp->comm);
  } else {
    pr_info("pid does not exists!\n");
  }
  return original_kill(regs);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
asmlinkage long hook_exec_fn(const char __user *filename,
                             const char __user *const argv[],
                             const char __user *const envp[]) {
  char *user_filename;
  int len = 0, copied;
  len = strnlen_user(filename, PATH_MAX);
  user_filename = (char *)kmalloc(len + 1, GFP_KERNEL);
  copied = strncpy_from_user(user_filename, filename, len);
  pr_info("execve %s !\n", user_filename);
  kfree(user_filename);
  return ((sys_execve_fn)(original_execve))(filename, argv, envp);
}
#else
asmlinkage long hook_exec_fn(const struct pt_regs *regs) {
  char *user_filename;
  int len = 0, copied;
  char __user *filename;
#if defined(CONFIG_ARM64)
  filename = (char __user *)regs->regs[0];
#endif
#if defined(CONFIG_X86_64)
  filename = (char __user *)regs->di;
#endif
  len = strnlen_user(filename, PATH_MAX);
  user_filename = (char *)kmalloc(len + 1, GFP_KERNEL);
  memset(user_filename, 0, len + 1);
  copied = strncpy_from_user(user_filename, filename, len);
  pr_info("execve %s !\n", user_filename);
  kfree(user_filename);
  return original_execve(regs);
}
#endif

static int init_syscall_table(void) {
  syscall_table = (syscall_fn_t *)lookup_name("sys_call_table");
  pr_info("syscall_table addr: %lx\n", (unsigned long)syscall_table);
  if (syscall_table == 0)
    return -EFAULT;
  return 0;
}
struct syscall_hook hooks[] = {
    HOOK("sys_kill", __NR_kill, original_kill, hook_kill_fn),
    HOOK("sys_execve", __NR_execve, original_execve, hook_exec_fn),

};
static int __init modinit(void) {
  int ret;
  ret = init_syscall_table();
  if (ret) {
    pr_err("init_syscall_table failed: %d\n", ret);
    return ret;
  }
  ret = install_hooks(syscall_table, hooks, ARRAY_SIZE(hooks));
  if (ret) {
    pr_info("hook failed!\n");
    return ret;
  }
  pr_info("install syscall hook done\n");
  return 0;
}

static void __exit modexit(void) {
  int res;
  res = uninstall_hooks(syscall_table, hooks, ARRAY_SIZE(hooks));
  if (res)
    pr_err("uninstall hook failed!\n");
  pr_info("exited\n");
}

module_init(modinit);
module_exit(modexit);
