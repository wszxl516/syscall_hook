#include "kapi.h"
#include "linux/printk.h"
static char *get_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, PATH_MAX) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}



static const char __user *get_user_arg_ptr(const char __user *const __user *argv, int nr)
{
	const char __user *native = NULL;

	if (get_user(native, argv + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

static int count(const char __user *const __user *argv, int max)
{
	int i = 0;

	if (argv != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;
			++i;
		}
	}
	return i;
}


void dump_strings(const char __user *const __user *strings){
	int len = 0, i=0;
	char *kaddr = NULL;
	int argc = count(strings,  MAX_ARG_STRINGS);
	for(i=0; i < argc; i++) {
		const char __user *str;
		str = get_user_arg_ptr(strings, i);
		if (IS_ERR(str))
			goto out;
		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len)
			goto out;
		kaddr = kmalloc(len + 1, GFP_KERNEL);
		memset(kaddr, 0, len + 1);
		if (copy_from_user(kaddr, str, len)) {
			kfree(kaddr);
			goto out;
		}
		printk(KERN_CONT "%s ", kaddr);
		kfree(kaddr);
	}
	out:
		printk("\n");
}

void dump_exec_info(const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp)
{
	char *kernel_filename = get_filename(filename);
	printk("execve: %s \n", kernel_filename);
	kfree(kernel_filename);
	printk(KERN_CONT "argv: ");
	dump_strings(argv);
	printk(KERN_CONT "env: ");
	dump_strings(envp);

}