#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>


struct pagetable_layout_info kernel_pgtbl_info = {
	.pgdir_shift = PGDIR_SHIFT,
	.pmd_shift = PMD_SHIFT,
	.page_shift = PAGE_SHIFT
};

SYSCALL_DEFINE2(get_pagetable_layout,
		struct pagetable_layout_info __user *, pgtbl_info, int,
		size)
{
	if (size != sizeof(kernel_pgtbl_info))
		return -EINVAL;
	if (copy_to_user
	    (pgtbl_info, &kernel_pgtbl_info, sizeof(kernel_pgtbl_info)))
		return -EFAULT;
	return 0;
}

int remap_every_page_pte(struct task_struct *curr,
			 struct expose_info *all_info,
			 pte_t *addr_need_to_map,
			 unsigned long map_des_addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(curr->mm, map_des_addr);

	if (remap_pfn_range
	    (vma, map_des_addr, (__pa(addr_need_to_map) >> PAGE_SHIFT),
	     PAGE_SIZE, vma->vm_page_prot)) {
		return -EINVAL;
	}
	return 0;
}

int page_fault_remap(unsigned long addr)
{
	unsigned long now_addr;
	unsigned long offset;
	struct expose_info *all_info;
	struct mm_struct *mm;

	pgd_t *des_pgd;
	pud_t *des_pud;
	pmd_t *des_pmd;
	pte_t *des_pte;

	unsigned long user_pte;

	all_info = &(current->inspector->all_info);
	now_addr = addr >> PMD_SHIFT << PMD_SHIFT;
	offset = (all_info->begin_vaddr) >> PMD_SHIFT << PMD_SHIFT;
	mm = current->mm;

	des_pgd = pgd_offset(mm, now_addr);
	if (pgd_none_or_clear_bad(des_pgd))
		return -EFAULT;

	des_pud = pud_offset(des_pgd, now_addr);
	if (pud_none_or_clear_bad(des_pud))
		return -EFAULT;

	des_pmd = pmd_offset(des_pud, now_addr);
	if (pmd_none_or_clear_bad(des_pmd))
		return -EFAULT;

	des_pte = pte_offset_map(des_pmd, now_addr);

	user_pte =
	    ((now_addr - offset) >> PAGE_SHIFT) * sizeof(unsigned long) +
	    all_info->page_table_addr;

	if (remap_every_page_pte
	    (current->inspector, all_info, des_pte, user_pte) < 0)
		return -EFAULT;
	return 0;
}


int pte_remap(struct expose_info *all_info)
{
	unsigned long temp;
	unsigned long now_addr;
	unsigned long offset;
	struct mm_struct *mm;

	unsigned long user_pte;

	pgd_t *des_pgd;
	pud_t *des_pud;
	pmd_t *des_pmd;
	pte_t *des_pte;

	mm = all_info->task->mm;

	now_addr = (all_info->begin_vaddr) >> PMD_SHIFT << PMD_SHIFT;
	offset = now_addr;


	do {

		temp = now_addr + PMD_SIZE;
		des_pgd = pgd_offset(mm, now_addr);
		if (pgd_none_or_clear_bad(des_pgd))
			continue;


		des_pud = pud_offset(des_pgd, now_addr);
		if (pud_none_or_clear_bad(des_pud))
			continue;

		des_pmd = pmd_offset(des_pud, now_addr);
		if (pmd_none_or_clear_bad(des_pmd))
			continue;


		des_pte = pte_offset_map(des_pmd, now_addr);

		user_pte =
		    ((now_addr -
		      offset) >> PAGE_SHIFT) * sizeof(unsigned long) +
		    all_info->page_table_addr;

		if (remap_every_page_pte
		    (current, all_info, des_pte, user_pte) < 0)
			return -EFAULT;

	} while (now_addr = temp, now_addr < all_info->end_vaddr);

	return 0;
}

struct vm_area_struct *check_and_get_vma(unsigned long address,
					 unsigned long size)
{
	struct vm_area_struct *vma;

	vma = find_vma(current->mm, address);

	if (vma->vm_end - address < size)
		return NULL;

	return vma;
}

SYSCALL_DEFINE6(expose_page_table, pid_t, pid, unsigned long, fake_pgd,
		unsigned long, fake_pmds, unsigned long, page_table_addr,
		unsigned long, begin_vaddr, unsigned long, end_vaddr)
{

	struct task_struct *expose_task;
	struct mm_struct *mm;
	struct vm_area_struct *pgd_vma;
	struct vm_area_struct *pmds_vma;
	struct vm_area_struct *ptes_vma;
	unsigned long pgd_size, pmds_size, ptes_size;

	unsigned long pgd_entry, pmd_entry;

	unsigned long base_pmd, base_pte;
	unsigned long now_addr;
	unsigned long offset;

	if (pid < 0)
		return -EINVAL;

	expose_task = find_task_by_vpid(pid);

	if (!expose_task)
		return -EINVAL;

	mm = expose_task->mm;

	pgd_size =
	    (pgd_index(end_vaddr) - pgd_index(begin_vaddr) +
	     1) * sizeof(unsigned long);
	pmds_size = pgd_size * PTRS_PER_PMD;
	ptes_size = pmds_size * PTRS_PER_PTE;

	pgd_vma = check_and_get_vma(fake_pgd, pgd_size);
	pmds_vma = check_and_get_vma(fake_pmds, pmds_size);
	ptes_vma = check_and_get_vma(page_table_addr, ptes_size);

	if (!pgd_vma || !pmds_vma || !ptes_vma)
		return -EINVAL;

	now_addr = begin_vaddr >> PMD_SHIFT << PMD_SHIFT;
	offset = now_addr;

	while (now_addr < end_vaddr) {

		pgd_entry =
		    pgd_index(now_addr) * sizeof(unsigned long) + fake_pgd;
		base_pmd =
		    (pgd_index(now_addr) - pgd_index(offset)) * PAGE_SIZE +
		    fake_pmds;
		if (copy_to_user
		    ((void *) pgd_entry, &base_pmd, sizeof(unsigned long)))
			return -EINVAL;

		pmd_entry =
		    (pmd_index(now_addr)) * sizeof(unsigned long) +
		    base_pmd;
		base_pte =
		    ((now_addr -
		      offset) >> PAGE_SHIFT) * sizeof(unsigned long) +
		    page_table_addr;
		if (copy_to_user
		    ((void *) pmd_entry, &base_pte, sizeof(unsigned long)))
			return -EINVAL;

		now_addr += PMD_SIZE;
	}

	current->all_info.task = expose_task;
	current->all_info.fake_pgd = fake_pgd;
	current->all_info.fake_pmds = fake_pmds;
	current->all_info.page_table_addr = page_table_addr;
	current->all_info.begin_vaddr = begin_vaddr;
	current->all_info.end_vaddr = end_vaddr;
	current->all_info.pgd_vma = pgd_vma;
	current->all_info.pmds_vma = pmds_vma;
	current->all_info.ptes_vma = ptes_vma;

	down_read(&(mm->mmap_sem));

	if (pte_remap(&current->all_info) < 0) {
		up_read(&(mm->mmap_sem));
		return -EFAULT;
	}
	expose_task->inspector = current;

	up_read(&(mm->mmap_sem));

	return 0;

}
