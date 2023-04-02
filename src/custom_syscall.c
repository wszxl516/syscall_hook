#include "custom_syscall.h"
#include "kapi.h"

syscall_fn_t     org_sys_execve = NULL;
syscall_fn_t     org_sys_kill = NULL;
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

  return ((sys_kill_fn)(org_sys_kill))(pid, sig);
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
  return org_sys_kill(regs);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
asmlinkage long hook_exec_fn(const char __user *filename,
                             const char __user *const argv[],
                             const char __user *const envp[]) {
  dump_exec_info(filename, argv, envp);
  return ((sys_execve_fn)(org_sys_execve))(filename, argv, envp);
}
#else
asmlinkage long hook_exec_fn(const struct pt_regs *regs) {
  char *user_filename;
  int len = 0, copied;
  char __user *filename;
  const char __user *const __user *argv;
  const char __user *const __user *envp;
#if defined(CONFIG_ARM64)
  filename = (char __user *)regs->regs[0];
  argv = (const char __user *const __user)regs->regs[1];
  envp = (const char __user *const __user)regs->regs[2];
#endif
#if defined(CONFIG_X86_64)
  filename = (char __user *)regs->di;
  argv = (const char __user *const __user)regs->si;
  envp = (const char __user *const __user)regs->dx;
#endif
  dump_exec_info(filename, argv, envp);
  return org_sys_execve(regs);
}
#endif