#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/slab.h>
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

int remap_every_page_pte(struct expose_info * all_info, unsigned long addr_need_to_map, unsigned long map_des_addr){
	struct vm_area_struct * vma;

	vma = find_vma(current->mm, map_des_addr);

	if(remap_pfn_range(vma,map_des_addr,__pa(addr_need_to_map),PAGE_SIZE,vma->vm_page_prot)){
		return -EINVAL;
	}
	return 0;
}

int pte_remap(struct expose_info * all_info, struct vm_area_struct * now_area){
	unsigned long temp;
	unsigned long now_addr;
	unsigned long offset;
	struct mm_struct * mm;

	unsigned long pgd_entry, pmd_entry;

	unsigned long user_pmd,user_pte;

	pgd_t * des_pgd;
	pud_t * des_pud;
	pmd_t * des_pmd;

	mm = all_info->task->mm;

	now_addr = now_area->vm_start;
	offset = all_info->begin_vaddr;

	do{
		temp = pgd_addr_end(now_addr,now_area->vm_end);
		des_pgd = pgd_offset(mm, now_addr);
		if(pgd_none_or_clear_bad(des_pgd))
			continue;

		des_pud = pud_offset(des_pgd,now_addr);
		if(pud_none_or_clear_bad(des_pud))
			continue;

		des_pmd = pmd_offset(des_pud,now_addr);
		if (pmd_none_or_clear_bad(des_pmd))
			continue;

		pgd_entry = (pgd_index(now_addr) - pgd_index(offset))*sizeof(unsigned long) + all_info->fake_pgd;
		user_pmd = all_info->fake_pmds + (pgd_index(now_addr) - pgd_index(offset)) * PAGE_SIZE;
		/*It should use copy_to_user, will debug it futher*/
		*(unsigned long *)pgd_entry = user_pmd;

		pmd_entry = *(unsigned long *)pgd_entry + pmd_index(now_addr) * sizeof(unsigned long);
		user_pte = all_info->page_table_addr 
			+ (pgd_index(now_addr) - pgd_index(offset))*sizeof(unsigned long) * PTRS_PER_PGD * PAGE_SIZE
			+ pmd_index(now_addr) * PAGE_SIZE;
		*(unsigned long *)pmd_entry = user_pte;

		if(remap_every_page_pte(all_info,now_addr,user_pte) < 0 )
			return -EFAULT;


	}while(now_addr = temp,temp!=now_area->vm_end);

	return 0;
}

struct vm_area_struct *  check_and_get_vma(unsigned long address,unsigned long size){
	struct vm_area_struct * vma;

	vma = find_vma(current->mm,address);

	if(vma->vm_end - address < size)
		return NULL;

	return vma;
}

SYSCALL_DEFINE6(expose_page_table, pid_t, pid,unsigned long, fake_pgd,
	unsigned long, fake_pmds, unsigned long, page_table_addr,
	unsigned long, begin_vaddr, unsigned long, end_vaddr){

	struct task_struct * expose_task;
	struct mm_struct * mm;
	struct vm_area_struct * pgd_vma;
	struct vm_area_struct * pmds_vma;
	struct vm_area_struct * ptes_vma;
	struct expose_info * all_info;
	unsigned long pgd_size,pmds_size,ptes_size;
	struct vm_area_struct * now_area;

	if(pid < 0)
		return -EINVAL;

	expose_task = find_task_by_vpid(pid);

	if(!expose_task)
		return -EINVAL;

	mm = expose_task->mm;

	pgd_size = (pgd_index(end_vaddr) - pgd_index(begin_vaddr)+1) * sizeof(unsigned long);
	pmds_size = pgd_size * PTRS_PER_PMD;
	ptes_size = pmds_size * PTRS_PER_PTE;

	pgd_vma = check_and_get_vma(fake_pgd,pgd_size);
	pmds_vma = check_and_get_vma(fake_pmds,pmds_size);
	ptes_vma = check_and_get_vma(page_table_addr,ptes_size);

	if(!pgd_vma || !pmds_vma || !ptes_vma)
		return -EINVAL;

	memset((void *)fake_pgd,0,pgd_size);
	memset((void *)fake_pmds,0,pmds_size);
	memset((void *)page_table_addr,0,ptes_size);

	all_info = kmalloc(sizeof(struct expose_info),GFP_KERNEL);
	all_info->task = expose_task;
	all_info->fake_pgd = fake_pgd;
	all_info -> fake_pmds = fake_pmds;
	all_info-> page_table_addr = page_table_addr;
	all_info-> begin_vaddr = begin_vaddr;
	all_info->end_vaddr = end_vaddr;
	all_info->pgd_vma = pgd_vma;
	all_info->pmds_vma = pmds_vma;
	all_info->ptes_vma = ptes_vma;

	down_read(&(mm->mmap_sem));

	now_area = find_vma(expose_task->mm,begin_vaddr);

	do{
		if(pte_remap(all_info,now_area) < 0){
			up_read(&(mm->mmap_sem));
			kfree(all_info);
			return -EFAULT;
		}
		now_area = now_area->vm_next;
	}while(now_area->vm_start < end_vaddr);

	up_read(&(mm->mmap_sem));
	kfree(all_info);
	return 0;

}
