#include "symbol.h"
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
typedef unsigned long (*kallsyms_lookup_name_fn)(const char *name);
static kallsyms_lookup_name_fn kallsyms_lookup_name_addr= NULL;
#if defined(CONFIG_X86_64)
unsigned long lookup_name(const char *name)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0) 
        struct kprobe kp;
        if(kallsyms_lookup_name_addr == NULL)
        {  
            kp.symbol_name = "kallsyms_lookup_name";
            if(register_kprobe(&kp) < 0)
            {
                pr_info("can not find kallsyms_lookup_name address\n");
                return 0;
            }
            kallsyms_lookup_name_addr = (kallsyms_lookup_name_fn)kp.addr;
            pr_info("kallsyms_lookup_name address: %lx\n", (unsigned long)kallsyms_lookup_name_addr);
            unregister_kprobe(&kp);
        }
        return kallsyms_lookup_name_addr(name);
    #else
        return  kallsyms_lookup_name(name);
    #endif
}
#endif
#if defined(CONFIG_ARM64)
unsigned long kaddr_lookup_name(const char *fname_raw)
{
    int i;
    unsigned long kaddr;
    char *fname_lookup, *fname;
    fname_lookup = kzalloc(NAME_MAX, GFP_KERNEL);
    if (!fname_lookup)
        return 0;
    fname = kzalloc(strlen(fname_raw)+4, GFP_KERNEL);
    if (!fname)
        return 0;
    strcpy(fname, fname_raw);
    strcat(fname, "+0x0");
    kaddr = (unsigned long) &sprint_symbol;
    kaddr &= 0xffffffffff000000;
    for ( i = 0x0 ; i < 0x100000 ; i++ )
    {
        sprint_symbol(fname_lookup, kaddr);
        if ( strncmp(fname_lookup, fname, strlen(fname)) == 0 )
        {
            kfree(fname_lookup);
            return kaddr;
        }
        kaddr += 0x10;
    }
    kfree(fname_lookup);
    return 0;
}

unsigned long lookup_name(const char *name)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0) 
        if(kallsyms_lookup_name_addr == NULL)
        {  
            kallsyms_lookup_name_addr = (kallsyms_lookup_name_fn)kaddr_lookup_name("kallsyms_lookup_name");
            if(kallsyms_lookup_name_addr == NULL)
            {
                pr_info("can not find kallsyms_lookup_name address\n");
                return 0;
            }
            pr_info("kallsyms_lookup_name address: %lx\n", (unsigned long)kallsyms_lookup_name_addr);
        }
        return kallsyms_lookup_name_addr(name);
    #else
        return  kallsyms_lookup_name(name);
    #endif
}
#endif
