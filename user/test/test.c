#include <linux/unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <sys/types.h>
#include "stdio.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <inttypes.h>

#define __NR_get_pagetable_layout 245

struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};

int main(int argc, char const *argv[])
{
	int size = sizeof(struct pagetable_layout_info);
	struct pagetable_layout_info *pgtbl_info;
	pgtbl_info = malloc(size);
	if (!pgtbl_info) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		return 0;
	}
	printf("%d\n", size);
	if (syscall(__NR_get_pagetable_layout, pgtbl_info, size) != 0) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		return 0;
	}
	printf("pgdir_shift:\t%" PRIu32 "\n", pgtbl_info->pgdir_shift);
	printf("pmd_shift:\t%" PRIu32 "\n", pgtbl_info->pmd_shift);
	printf("page_shift:\t%" PRIu32 "\n", pgtbl_info->page_shift);
	return 0;
}
