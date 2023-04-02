#include "hook.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include "custom_syscall.h"

#if !defined(CONFIG_X86_64) && !defined(CONFIG_ARM64)
#error Currently only x86_64 and arm64 architecture is supported
#endif

MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Syscall hook on linux");
MODULE_AUTHOR("sun");
MODULE_LICENSE("GPL");

syscall_hook_t hooks[] = {
    HOOK_KILL,
    HOOK_EXECVE,

};
static int __init modinit(void) {
  int ret;
  ret = install_hooks(hooks, ARRAY_SIZE(hooks));
  if (ret) {
    pr_info("hook failed!\n");
    return ret;
  }
  pr_info("install syscall hook done\n");
  return 0;
}

static void __exit modexit(void) {
  int res;
  res = uninstall_hooks(hooks, ARRAY_SIZE(hooks));
  if (res)
    pr_err("uninstall hook failed!\n");
  pr_info("exited\n");
}

module_init(modinit);
module_exit(modexit);
