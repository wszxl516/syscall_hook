#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h> 
#include "hook.h"
static syscall_fn_t *syscall_table;
static syscall_fn_t original_kill;
static syscall_fn_t original_execve;
#if  !defined(CONFIG_X86_64) && !defined(CONFIG_ARM64)
#error Currently only x86_64 and arm64 architecture is supported
#endif
#define HOOK(_name , _nr, _org, _custom)    \
    { \
        .custom_syscall = (syscall_fn_t)_custom, \
        .org_syscall = &_org, \
        .syscall_nr = _nr, \
        .name = (_name) \
    }
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Syscall hook on linux");
MODULE_AUTHOR("sun");
MODULE_LICENSE("GPL");
asmlinkage long hook_kill_fn(const struct pt_regs *regs)
{
    struct task_struct *taskp;
	pid_t pid, sig;
    #if defined(CONFIG_ARM64)
        pid = regs->regs[0];
        sig = regs->regs[1];
    #endif
	#if defined(CONFIG_X86_64)
		pid = regs->di;
		sig = regs->si;
	#endif
	taskp = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	pr_info("send signal %d to pid: %d name : %s\n", sig, pid, taskp->comm);
    return original_kill(regs);
}

asmlinkage long hook_exec_fn(const struct pt_regs *regs)
{
    int ret;
	char filename[NAME_MAX];
    char __user * filename_user;
    memset(filename, 0, NAME_MAX);
    #if defined(CONFIG_ARM64)
        filename_user = (char __user *)regs->regs[0];
    #endif
	#if defined(CONFIG_X86_64)
        filename_user = (char __user *)regs->di;
	#endif
    ret = copy_from_user(filename, filename_user, strlen(filename_user));
    if (ret<0)
    {
        pr_err("failed get execve filename!\n");
        return -EFAULT;
    }
    
	pr_info("execve: %s\n", filename);
    return original_execve(regs);
}

static int init_syscall_table(void)
{
    syscall_table = (syscall_fn_t *)lookup_name("sys_call_table");
    pr_info("syscall_table addr: %lx\n", (unsigned long)syscall_table);
    if(syscall_table == 0)
	    return -EFAULT;
    return 0;
}
struct syscall_hook kill_hook[] = {
    HOOK("syscall_kill", __NR_kill, original_kill, hook_kill_fn),
    HOOK("syscall_execve", __NR_execve, original_execve, hook_exec_fn),
};
static int __init modinit(void)
{
    int ret;
    ret = init_syscall_table();
    if(ret)
    {
        pr_err("init_syscall_table failed: %d\n", ret);
        return ret;
    }
    ret = install_hooks(syscall_table, kill_hook, ARRAY_SIZE(kill_hook));
    pr_info("original_kill addr: %lx\n", (unsigned long)original_kill);
    if(ret)
    {
        pr_info("hook __NR_kill failed!\n");
        return ret;
    }
    pr_info("install syscall hook done\n");
    return 0;
}

static void __exit modexit(void)
{
    int res;
    res = uninstall_hooks(syscall_table, kill_hook, ARRAY_SIZE(kill_hook));
    if(res)
        pr_err("uninstall hook failed!\n");
    pr_info("exited\n");
}

module_init(modinit);
module_exit(modexit);
