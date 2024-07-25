/* email: keorapete.finger@yahoo.com
 * KVM API Documentation https://docs.kernel.org/virt/kvm/api.html 
 */
#include <stdio.h>			/* printf */
#include <string.h>			/* memcpy */
#include <fcntl.h>			/* open */
#include <unistd.h>			/* close */
#include <sys/mman.h>			/* mmap */
#include <sys/ioctl.h>			/* ioctl calls */
#include <linux/kvm.h>			/* KVM_GET_API_VERSION */

#define TSS_ADDRESS			0xfffbd000
#define VM_MEM_SIZE 			0x8000

#define KVM_PERM			(O_RDWR | O_CLOEXEC)
#define VM_MEM_PERM			(PROT_EXEC | PROT_READ | PROT_WRITE)
#define VM_MEM_MAP_PERM			(MAP_SHARED | MAP_ANONYMOUS)
#define VCPU_MEM_PERM			(PROT_READ | PROT_WRITE, MAP_SHARED)
#define VCPU_MEM_MAP_PERM		(MAP_SHARED)

#define infinite_loop()			for (;;)

/* https://wiki.osdev.org/CPU_Registers_x86#CR0 */
#define CR0_PE	1u
#define CR0_PG	(1 << 31)

int main()
{
	int kvm_fd = open("/dev/kvm", KVM_PERM);

	int vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);

	/* the TSS is a structure used in x86 architecture to store information
	* about a task, such as processor registers, I/O map base address, and 
	* stack pointers. It plays a crucial role in handling hardware task 
	* switching and certain privileged operations.
	*/
	ioctl(vm_fd, KVM_SET_TSS_ADDR, TSS_ADDRESS);

	/* Allocate a block of memory in the host's virtual address space for
	 * our virtual machine (VM).
	 */
	void* host_virt_mem = mmap(0, VM_MEM_SIZE, VM_MEM_PERM, VM_MEM_MAP_PERM, -1, 0);

	/* inside the guest OS, memory addresses used by applications 
	 * are guest virtual addresses (GVA). The guest OS translates 
	 * these to guest physical addresses (GPA) using its own page 
	 * tables. KVM maps the guest physical addresses to host 
	 * virtual addresses (HVA) using the kvm_userspace_memory_region 
	 * structure. This mapping is defined by the host process running
	 * the virtual machine. The host OS manages the mapping of host 
	 * virtual addresses to host physical addresses using its own 
	 * memory management subsystem.
	 */
	struct kvm_userspace_memory_region vm_mem = {
		.guest_phys_addr	= 0x0L,
		.userspace_addr 	= (unsigned long) host_virt_mem,
		.memory_size 		= VM_MEM_SIZE,
		.slot 			= 0x0,
		.flags 			= 0x0
	};

	if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &vm_mem) < 0) {
		munmap(host_virt_mem, VM_MEM_SIZE);
		return -1;
	}

	int vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);

	/* setup protected mode by setting up Global Descriptor Table (GDT).
	 * 
	 * helpful information:
	 * - https://wiki.osdev.org/Global_Descriptor_Table
	 * - https://wiki.osdev.org/Segment_Selector
	 * 
	 * protected mode allows for the following:
	 * 	1. assess to 4 gb of RAM
	 * 	2. protect certain memory regions
	 * 	3. set appropriate privilage levels
	 */
	struct kvm_sregs vm_sregs;
	struct kvm_segment vm_seg = {
		.selector = 0x00,
		.present  = 0x01,
		.base 	= 0x0000,
		.limit 	= 0xffff,
		.type 	= 0x0b,
		.dpl 	= 0x00,
		.db 	= 0x01,
		.s = 0x01,
		.l = 0x00,
		.g = 0x01
	};

	ioctl(vcpu_fd, KVM_GET_SREGS, &vm_sregs);

	vm_sregs.cs = vm_seg;

	vm_seg.type = 0x03;
	vm_seg.selector = 0x00;

	vm_sregs.ds = vm_seg;
	vm_sregs.es = vm_seg;
	vm_sregs.fs = vm_seg;
	vm_sregs.gs = vm_seg;
	vm_sregs.ss = vm_seg;

	/* setup 32 bit paging with 4 Kib pages
	 * https://de.wikipedia.org/wiki/Paging#32-Bit-Paging
	 * https://wiki.osdev.org/CPU_Registers_x86#CR0
	 */
	unsigned int pgd_addr = 0x1000;
	unsigned int *pgd = (unsigned int*)(host_virt_mem + pgd_addr);

	/* the page directory and each page table consist of 1024 4-byte entries */
	unsigned int pg_addr = 0x2000;
	unsigned int *pg = (unsigned int*)(host_virt_mem + pg_addr);

	pgd[0] = pg_addr | 0x03;
	pg[0] = 0x03;

	vm_sregs.cr3 = pgd_addr;
	vm_sregs.cr0 = (CR0_PE | CR0_PG);

	ioctl(vcpu_fd, KVM_SET_SREGS, &vm_sregs);

	struct kvm_regs vpcu_regs = {
		.rflags = 0x02,
		.rip = 0x0000
	};

	ioctl(vcpu_fd, KVM_SET_REGS, &vpcu_regs);

	int vcpu_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, (void*) 0);
	void* vcpu_addr = mmap(0, vcpu_mmap_size, VCPU_MEM_PERM, VCPU_MEM_MAP_PERM, vcpu_fd, 0);
	
	struct kvm_run *vm_state = (struct kvm_run *) vcpu_addr;

	/* 32 bit program */
	static const char instr[] = {
		0xfc,						// 			cld
		0x66, 0x8d, 0x35, 0x15, 0x00, 0x00, 0x00,	// 			lea si, msg
		0x66, 0xb9, 0x0d, 0x00,				// 			mov cx, len
		0x66, 0xba, 0xe9, 0x00,				// 			mov dx, 0xe9
		0xac,						// again:		lodsb
		0xee,						// 			out dx, al
		0xe2, 0xfc,					// 			loop again
		0xf4,						// 			hlt
		0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
		0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a	// 			msg db "Hello World!", 0x0a
								//			len equ $-msg	
	};

	memcpy((char*) host_virt_mem, instr, sizeof(instr));

	infinite_loop() {
		ioctl(vcpu_fd, KVM_RUN, 0);

		switch(vm_state->exit_reason) {
		case KVM_EXIT_IO: 
			{
				if (vm_state->io.port == 0xe9)
                    			printf("%c", *(unsigned short*)((char*)vm_state + vm_state->io.data_offset));
				break;
			}
		case KVM_EXIT_HLT: 
			{
				printf("KVM halted...\n");
					goto exit;
			}
		default:
			printf("Unknown KVM (%d) state...\n", vm_state->exit_reason);
			goto exit;
		}
	}

exit:
	munmap(vcpu_addr, vcpu_mmap_size);
	munmap(host_virt_mem, VM_MEM_SIZE);

	close(vcpu_fd);
	close(vm_fd);
	close(kvm_fd);

	printf("Bye bye...\n");

	return 0;
}