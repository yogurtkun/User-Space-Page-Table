#include <linux/syscalls.h>
#include <linux/mm.h>
//#include <linux/mm_types.h>
//#include <linux/pfn.h>

// struct pagetable_layout_info {
// 	uint32_t pgdir_shift;
// 	uint32_t pmd_shift;
// 	uint32_t page_shift;
// };

struct pagetable_layout_info kernel_pgtbl_info = {
	.pgdir_shift = PGDIR_SHIFT,
	.pmd_shift = PMD_SHIFT,
	.page_shift = PAGE_SHIFT
};

SYSCALL_DEFINE2(get_pagetable_layout, struct pagetable_layout_info __user *,
		pgtbl_info, int, size)
{
	if (size != sizeof(kernel_pgtbl_info))
		return -EINVAL;
	if (copy_to_user(pgtbl_info, &kernel_pgtbl_info, sizeof(kernel_pgtbl_info)))
		return -EFAULT;
	return 0;
}
