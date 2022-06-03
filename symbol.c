#include "symbol.h"
typedef unsigned long (*kallsyms_lookup_name_fn)(const char *name);
kallsyms_lookup_name_fn kallsyms_lookup_name_addr=NULL;


unsigned long lookup_name(const char *name)
{
	struct kprobe kp;
    if(kallsyms_lookup_name_addr == NULL)
    {  
        kp.symbol_name = "kallsyms_lookup_name";
        if(register_kprobe(&kp) < 0)
        {
            pr_info("can not find symbol: %s address\n", name);
            return 0;
        }
        kallsyms_lookup_name_addr = (kallsyms_lookup_name_fn)kp.addr;
        pr_info("kallsyms_lookup_name address: %lx\n", (unsigned long)kallsyms_lookup_name_addr);
        unregister_kprobe(&kp);
    }
	return  kallsyms_lookup_name_addr(name);
}