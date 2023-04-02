#ifndef __SET_PAGE__
#define __SET_PAGE__
#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
struct page_change_data {
  pgprot_t set_mask;
  pgprot_t clear_mask;
};
int set_addr_rw(unsigned long addr);
int set_addr_ro(unsigned long addr);
typedef void (flush_tlb_kernel_range_t)(unsigned long start, unsigned long end);
#endif //__SET_PAGE__