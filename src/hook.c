#include "hook.h"
#include "asm-generic/errno-base.h"
#include "linux/gfp_types.h"
#include "linux/slab.h"
static syscall_fn_t *sys_call_table;

static int
replace_call_func (unsigned long handler, unsigned long orig_func,
                   unsigned long custom_func)
{
  unsigned char *tmp_addr = (unsigned char *)handler;
  int i = 0;
  do
    {
      /* in x86_64 the call instruction opcode is 0x8e, occupy 1+4
       * bytes(E8+offset) totally*/
      if (*tmp_addr == 0xe8)
        {
          int *offset = (int *)(tmp_addr + 1);
          if (((unsigned long)tmp_addr + 5 + *offset) == orig_func)
            {
              /* replace with my_func relative addr(offset) */
              *offset = custom_func - (unsigned long)tmp_addr - 5;
              pr_info (
                  "base addr: 0x%08lx, offset:%08lx, replace func: %08lx to "
                  "func: %08lx.\n",
                  (unsigned long)tmp_addr, (unsigned long)(*offset), orig_func,
                  custom_func);
              return 0;
            }
        }
      tmp_addr++;
    }
  while (i++ < 128);
  return 1;
}

static int
init_syscall_table (void)
{
  sys_call_table = (syscall_fn_t *)lookup_name ("sys_call_table");
  pr_info ("syscall_table addr: %lx\n", (unsigned long)sys_call_table);
  if (sys_call_table == 0)
    return -EFAULT;
  return 0;
}

int
install_hook (syscall_hook_t *hook)
{
  int res;
  unsigned long syscall_base_addr = 0;
  char *fname_lookup = (char *)kmalloc (NAME_MAX + 1, GFP_KERNEL);
  if (!fname_lookup)
    return -EFAULT;
  syscall_base_addr = (unsigned long)sys_call_table[hook->syscall_nr];
  sprint_symbol (fname_lookup, syscall_base_addr);
  if (strncmp (fname_lookup, "stub", 4) == 0)
    {
      res = set_addr_rw (syscall_base_addr);
      if (res != 0)
        {
          pr_err ("set sys_call_table writeable failed: %d\n", res);
          goto out;
        }
      res = replace_call_func ((unsigned long)syscall_base_addr,
                               lookup_name (hook->name),
                               (unsigned long)hook->custom_syscall);
      if (res != 0)
        goto out;
      res = set_addr_ro (syscall_base_addr);
      if (res != 0)
        {
          pr_err ("set sys_call_table read only failed: %d\n", res);
          goto out;
        }
      *hook->org_syscall = (syscall_fn_t)lookup_name (hook->name);
    }
  else
    {
      *hook->org_syscall = sys_call_table[hook->syscall_nr];
      pr_info ("org_fn addr: %lx\n", (unsigned long)*hook->org_syscall);
      res = set_addr_rw ((unsigned long)(sys_call_table + hook->syscall_nr));
      if (res != 0)
        {
          pr_err ("set sys_call_table writeable failed: %d\n", res);
          goto out;
        }
      sys_call_table[hook->syscall_nr] = hook->custom_syscall;
      res = set_addr_ro ((unsigned long)(sys_call_table + hook->syscall_nr));
      if (res != 0)
        {
          pr_err ("set sys_call_table read only failed: %d\n", res);
          goto out;
        }
    }
out:
  kfree (fname_lookup);
  return res;
}

int
uninstall_hook (syscall_hook_t *hook)
{
  int res = 0;
  char *fname_lookup = (char *)kmalloc (PATH_MAX + 1, GFP_KERNEL);
  unsigned long syscall_base_addr = 0;
  if (*hook->org_syscall == (syscall_fn_t)NULL)
    return 0;

  syscall_base_addr = (unsigned long)sys_call_table[hook->syscall_nr];
  sprint_symbol (fname_lookup, syscall_base_addr);
  if (strncmp (fname_lookup, "stub", 4) == 0)
    {
      res = set_addr_rw (syscall_base_addr);
      if (res != 0)
        {
          pr_err ("set sys_call_table writeable failed: %d\n", res);
          res = -EFAULT;
          goto out;
        }
      replace_call_func ((unsigned long)syscall_base_addr,
                         (unsigned long)hook->custom_syscall,
                         lookup_name (hook->name));
      res = set_addr_ro (syscall_base_addr);
      if (res != 0)
        {
          pr_err ("set sys_call_table read only failed: %d\n", res);
          goto out;
        }
    }
  else
    {
      res = set_addr_rw ((unsigned long)(sys_call_table + hook->syscall_nr));
      if (res != 0)
        {
          pr_err ("set sys_call_table writeable failed: %d\n", res);
          res = -EFAULT;
          goto out;
        }
      sys_call_table[hook->syscall_nr] = *hook->org_syscall;
      res = set_addr_ro ((unsigned long)(sys_call_table + hook->syscall_nr));
      if (res != 0)
        {
          pr_err ("set sys_call_table read only failed: %d\n", res);
          goto out;
        }
    }
out:
  kfree (fname_lookup);
  return res;
}

int
install_hooks (syscall_hook_t *hook, int hook_count)
{
  int i, ret;
  ret = init_syscall_table ();
  if (ret)
    {
      pr_err ("init_syscall_table failed: %d\n", ret);
      return ret;
    }
  for (i = 0; i < hook_count; i++)
    {
      pr_info ("install hook %s\n", hook[i].name);
      ret = install_hook (&hook[i]);
      if (ret)
        {
          pr_err ("install hooks failed uninstall theme!\n");
          uninstall_hooks (hook, hook_count);
          return ret;
        }
    }
  return 0;
}

int
uninstall_hooks (syscall_hook_t *hook, int hook_count)
{
  int i, ret;
  ret = init_syscall_table ();
  if (ret)
    {
      pr_err ("init_syscall_table failed: %d\n", ret);
      return ret;
    }
  for (i = 0; i < hook_count; i++)
    {
      pr_info ("uninstall hook %s\n", hook[i].name);
      ret = uninstall_hook (&hook[i]);
      if (ret)
        return ret;
    }
  return 0;
}