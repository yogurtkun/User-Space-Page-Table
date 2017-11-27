#include <linux/unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/sched.h>
#include <sys/mman.h>
#include <fcntl.h>

struct pagetable_layout_info {
     uint32_t pgdir_shift;
     uint32_t pmd_shift;
     uint32_t page_shift;
};

#define __NR_get_pagetable_layout 245

#define __NR_expose_page_table 246


int main(int argc, char const *argv[])
{
	int i=0;
	struct pagetable_layout_info pgtbl_info;
	int info_size = sizeof(struct pagetable_layout_info);

	long x = syscall(__NR_get_pagetable_layout, &pgtbl_info, info_size);

	if(x<0) {
		printf("get pagetable layout information failed!");
		return -1;
	}

	// printf("pgdir_shift:\t%" PRIu32 "\n", pgtbl_info->pgdir_shift);
	// printf("pmd_shift:\t%" PRIu32 "\n", pgtbl_info->pmd_shift);
	// printf("page_shift:\t%" PRIu32 "\n", pgtbl_info->page_shift);

	pid_t pid;
	unsigned long *fake_pgd = NULL;
	unsigned long *fake_pmds = NULL;
	unsigned long *page_table_addr = NULL;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;

	/****to do: heck the arguments****/

	pid = atoi(argv[3]);
	begin_vaddr = strtol(argv[4],NULL,16);
	end_vaddr = strtol(argv[5],NULL,16);

	int fd = open("/dev/zero", O_RDONLY);

	unsigned long interval = end_vaddr - begin_vaddr;
	unsigned int pgd_entries = 1+(interval>>pgtbl_info.pgdir_shift);
	unsigned int pgd_entry_size = 1<<(pgtbl_info.page_shift- 
		(pgtbl_info.pgdir_shift-pgtbl_info.pmd_shift));
	unsigned long pgd_size = pgd_entries * pgd_entry_size;
	unsigned long pmds_size = pgd_entries * (1<<pgtbl_info.page_shift);
	unsigned long ptes_size = pgd_entries * (1<<pgtbl_info.pmd_shift);


	fake_pgd = mmap(NULL, pgd_size,
  					PROT_WRITE | PROT_READ,
  					MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	
	if (fake_pgd == MAP_FAILED) {
		printf("Error: mmap\n");
		return -1;
	}	

	fake_pmds = mmap(NULL, pmds_size,
					PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_SHARED, -1, 0);

	if (fake_pmds == MAP_FAILED) {
		printf("Error: mmap\n");
		return -1;
	}

	page_table_addr = mmap(NULL, ptes_size,
			PROT_READ, 
			MAP_ANONYMOUS | MAP_SHARED, fd, 0);

	if (page_table_addr == MAP_FAILED) {
		printf("Error: mmap\n");
		return -1;
	}

	close(fd);

	long y = syscall(__NR_expose_page_table, pid,
                    (unsigned long) fake_pgd,
                    (unsigned long) fake_pmds,
                    (unsigned long) page_table_addr,
                    (unsigned long) begin_vaddr,
                    (unsigned long) end_vaddr);

	if (y<0) {
		printf("expose pagetable failed!");
		return -1;
	}


	unsigned long *page;
	//page = page_table_addr;

	unsigned long va_addr;
	//va_addr = begin_vaddr;

	for (i=0;i<ptes_size/sizeof(unsigned long);++i) {
	//for (;page<page_table_addr+ptes_size;++page) {
		page = page_table_addr+i;
		va_addr = begin_vaddr + i*(1<<pgtbl_info.page_shift);
		if ((*page)==0) 
			continue;

		printf("0x%lx ", va_addr);
		printf("0x%lx ", *page);
		printf("\n");

	}




	return 0;

}