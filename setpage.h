#ifndef __SET_PAGE__
#define __SET_PAGE__
#include <asm/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/tlbflush.h> 
struct page_change_data {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};
int set_addr_rw(unsigned long addr);
int set_addr_ro(unsigned long addr);
#endif//__SET_PAGE__