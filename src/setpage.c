#include "setpage.h"
#include "symbol.h"
#if defined(CONFIG_ARM64)
struct mm_struct *init_mm_ptr = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
static inline int change_page_range(pte_t *ptep, pgtable_t token,
                                    unsigned long addr, void *data)
#else
static inline int change_page_range(pte_t *ptep, unsigned long addr, void *data)
#endif
{
  struct page_change_data *cdata = data;
  pte_t pte = READ_ONCE(*ptep);

  pte = clear_pte_bit(pte, cdata->clear_mask);
  pte = set_pte_bit(pte, cdata->set_mask);

  set_pte(ptep, pte);
  return 0;
}

static inline int __change_memory_common(unsigned long start,
                                         unsigned long size, pgprot_t set_mask,
                                         pgprot_t clear_mask) {
  struct page_change_data data;
  int ret;

  data.set_mask = set_mask;
  data.clear_mask = clear_mask;
  if (!init_mm_ptr)
    init_mm_ptr = (struct mm_struct *)lookup_name("init_mm");
  ret = apply_to_page_range(init_mm_ptr, start, size, change_page_range, &data);

  flush_tlb_kernel_range(start, start + size);
  return ret;
}

int set_addr_rw(unsigned long addr) {
  vm_unmap_aliases();
  return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE),
                                __pgprot(PTE_RDONLY));
}

int set_addr_ro(unsigned long addr) {
  vm_unmap_aliases();
  return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_RDONLY),
                                __pgprot(PTE_WRITE));
}
#endif

#if defined(CONFIG_X86_64)
static flush_tlb_kernel_range_t *flush_tlb_kernel_range_ptr;
static inline void   __flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
  if(!flush_tlb_kernel_range_ptr)
    flush_tlb_kernel_range_ptr = (flush_tlb_kernel_range_t*)lookup_name("flush_tlb_kernel_range");
  if(flush_tlb_kernel_range_ptr)
    flush_tlb_kernel_range_ptr(start, end);
}
typedef pte_t *(*lookup_address_fn)(unsigned long address, unsigned int *level);
lookup_address_fn lookup_address_addr = NULL;

int set_addr_rw(unsigned long addr) {
  pte_t *pte;
  unsigned int level;
  if (!lookup_address_addr)
    lookup_address_addr = (lookup_address_fn)lookup_name("lookup_address");
  pte = lookup_address_addr(addr, &level);
  set_pte_atomic(pte, pte_set_flags(*pte, _PAGE_RW));
  __flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
  return 0;
}

int set_addr_ro(unsigned long addr) {

  pte_t *pte;
  unsigned int level;
  if (!lookup_address_addr)
    lookup_address_addr = (lookup_address_fn)lookup_name("lookup_address");
  pte = lookup_address_addr(addr, &level);
  set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
  __flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
  return 0;
}
#endif
