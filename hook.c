#include "hook.h"
int install_hook(syscall_fn_t *sys_call_table, int syscall_NR, syscall_fn_t hook_fn, syscall_fn_t *org_fn)
{
    int res;
    *org_fn = sys_call_table[syscall_NR];
    pr_info("org_fn addr: %lx\n", (unsigned long)*org_fn);
    res = set_addr_rw((unsigned long)(sys_call_table + syscall_NR));
    if (res != 0) {
        pr_err("set sys_call_table writeable failed: %d\n", res);
        return res;
    }

    sys_call_table[syscall_NR] = hook_fn;
    res = set_addr_ro((unsigned long)(sys_call_table + syscall_NR));
    if (res != 0) {
        pr_err("set sys_call_table read only failed: %d\n", res);
        return res;
    }
    return 0;
}

int uninstall_hook(syscall_fn_t *sys_call_table, int syscall_NR, syscall_fn_t *org_fn)
{
    int res;
    res = set_addr_rw((unsigned long)(sys_call_table + syscall_NR));
    if (res != 0) {
        pr_err("set sys_call_table writeable failed: %d\n", res);
        return -EFAULT;
    }
    sys_call_table[syscall_NR] = *org_fn;
    res = set_addr_ro((unsigned long)(sys_call_table + syscall_NR));
    if (res != 0)
    {
        pr_err("set sys_call_table read only failed: %d\n", res);
        return res;
    }
    return 0;
}