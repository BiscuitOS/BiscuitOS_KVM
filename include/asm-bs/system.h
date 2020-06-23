#ifndef _BISCUITOS_SYSTEM_H
#define _BISCUITOS_SYSTEM_H

#define write_cr4_bs(x)	__asm__ __volatile__("movl %0, %%cr4" : : "r" (x))

#define read_cr4_bs()						\
({								\
	unsigned int __dummy;					\
	__asm__(						\
		"movl %%cr4, %0\n\t"				\
		: "=r" (__dummy));				\
	__dummy;						\
})

#endif
