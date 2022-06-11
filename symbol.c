#include "symbol.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
	#include <linux/kallsyms.h>
#else
    #include <linux/kprobes.h>
    typedef unsigned long (*kallsyms_lookup_name_fn)(const char *name);
    static kallsyms_lookup_name_fn kallsyms_lookup_name_addr= NULL;
#endif

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
