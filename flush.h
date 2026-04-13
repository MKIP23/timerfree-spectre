#ifndef FLUSH_H
#define FLUSH_H

#ifdef C910

// T-Head C910 (BeagleV-Ahead) custom instruction: DCACHE.CIVA
static inline void flush(void *p) {
    asm volatile(
        "xor a7, a7, a7\n\t"
        "add a7, a7, %0\n\t"
        ".long 0x0278800b\n\t"   // DCACHE.CIVA a7
        : : "r"(p) : "a7", "memory"
    );
    asm volatile("fence rw, rw" ::: "memory");
}

#else

// Standard RISC-V Zicbom extension (gem5)
static inline void flush(void *p) {
    asm volatile(
        "mv t0, %0\n\t"
        "cbo.flush 0(t0)\n\t"
        : : "r"(p) : "t0", "memory"
    );
    asm volatile("fence rw, rw" ::: "memory");
}

#endif

#endif // FLUSH_H
