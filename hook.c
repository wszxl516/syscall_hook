#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h> 
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <linux/kconfig.h>
#include "setpage.h"
#include "symbol.h"
#if defined(CONFIG_X86_64)
typedef long (*syscall_fn_t)(const struct pt_regs *regs);
#endif
static syscall_fn_t *syscall_table;
static syscall_fn_t original_kill;

#if  !defined(CONFIG_X86_64) && !defined(CONFIG_ARM64)
#error Currently only x86_64 and arm64 architecture is supported
#endif
static long hook_kill(const struct pt_regs *regs)
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

static int __init modinit(void)
{
    int res;
    pr_info("init\n");
    syscall_table = (syscall_fn_t *)lookup_name("sys_call_table");
    pr_info("syscall_table addr: %lx\n", (unsigned long)syscall_table);
    original_kill = syscall_table[__NR_kill];
    pr_info("original_kill addr: %lx\n", (unsigned long)original_kill);
    res = set_addr_rw((unsigned long)(syscall_table + __NR_kill));
    if (res != 0) {
        pr_err("set_page_rw() failed: %d\n", res);
        return res;
    }

    syscall_table[__NR_kill] = hook_kill;

    res = set_addr_ro((unsigned long)(syscall_table + __NR_kill));
    if (res != 0) {
        pr_err("set_page_ro() failed: %d\n", res);
        return res;
    }

    pr_info("init done\n");

    return 0;
}

static void __exit modexit(void)
{
    int res;

    pr_info("exit\n");
    res = set_addr_rw((unsigned long)(syscall_table + __NR_kill));
    if (res != 0) {
        pr_err("set_page_rw() failed: %d\n", res);
        return;
    }

    syscall_table[__NR_kill] = original_kill;
    res = set_addr_ro((unsigned long)(syscall_table + __NR_kill));
    if (res != 0)
        pr_err("set_page_ro() failed: %d\n", res);

    pr_info("goodbye\n");
}

module_init(modinit);
module_exit(modexit);
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Syscall hook on linux");
MODULE_AUTHOR("sun");
MODULE_LICENSE("GPL");