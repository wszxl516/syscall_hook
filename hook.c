#include "hook.h"
inline int install_hook(syscall_fn_t *sys_call_table, struct syscall_hook *hook)
{
    int res;
    *hook->org_syscall = sys_call_table[hook->syscall_nr];
    pr_info("org_fn addr: %lx\n", (unsigned long)*hook->org_syscall);
    res = set_addr_rw((unsigned long)(sys_call_table + hook->syscall_nr));
    if (res != 0) {
        pr_err("set sys_call_table writeable failed: %d\n", res);
        return res;
    }

    sys_call_table[hook->syscall_nr] = hook->custom_syscall;
    res = set_addr_ro((unsigned long)(sys_call_table + hook->syscall_nr));
    if (res != 0) {
        pr_err("set sys_call_table read only failed: %d\n", res);
        return res;
    }
    return 0;
}

inline int uninstall_hook(syscall_fn_t *sys_call_table, struct syscall_hook *hook)
{
    int res;
    res = set_addr_rw((unsigned long)(sys_call_table + hook->syscall_nr));
    if (res != 0) {
        pr_err("set sys_call_table writeable failed: %d\n", res);
        return -EFAULT;
    }
    sys_call_table[hook->syscall_nr] = *hook->org_syscall;
    res = set_addr_ro((unsigned long)(sys_call_table + hook->syscall_nr));
    if (res != 0)
    {
        pr_err("set sys_call_table read only failed: %d\n", res);
        return res;
    }
    return 0;
}

int install_hooks(syscall_fn_t *sys_call_table, struct syscall_hook *hook, int hook_count)
{
    int i, ret;
    for(i=0; i<hook_count; i++)
    {
        pr_info("install hook %s\n", hook[i].name);
        ret = install_hook(sys_call_table, &hook[i]);
        if(ret)
            return ret;
    }
    return 0;
}

int uninstall_hooks(syscall_fn_t *sys_call_table, struct syscall_hook *hook, int hook_count)
{
    int i, ret;
    for(i=0; i<hook_count; i++)
    {
        pr_info("uninstall hook %s\n", hook[i].name);
        ret = uninstall_hook(sys_call_table, &hook[i]);
        if(ret)
            return ret;
    }
    return 0;
}