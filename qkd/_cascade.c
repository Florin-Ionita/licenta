/*
 * Full Cascade reconciliation (Brassard & Salvail, 1994) with
 * back-propagation, written in C for performance.
 *
 * This is a faithful, teaching-grade implementation. Every step the protocol
 * makes is in the open: scheduled passes, BINCONF binary search, exact
 * accounting of every parity bit announced, and -- the crucial point of
 * "full" Cascade -- back-propagation across prior passes whenever a fix
 * exposes a previously-even (and therefore invisible) error pair.
 *
 * Exported entry point (called from qkd/_cascade.py via ctypes):
 *
 *   int cascade_reconcile(
 *       uint8_t *alice, uint8_t *bob, int32_t n,
 *       double qber, int32_t passes, uint64_t seed,
 *       int32_t *out_corrected, uint64_t *out_leaked);
 *
 *   alice, bob       : length-n arrays of 0/1 bits (uint8). On return, bob
 *                      has been mutated to match alice bit-by-bit.
 *   n                : number of bits in each array.
 *   qber             : estimated channel error rate (drives initial block size).
 *   passes           : number of scheduled Cascade passes (typical 4).
 *   seed             : 64-bit seed for the PCG random number generator.
 *   out_corrected    : (out) number of bit corrections applied.
 *   out_leaked       : (out) total number of public parity bits announced
 *                      (block parities + every BINCONF halving step).
 *
 *   return value     : 0 on success (alice == bob on return),
 *                      -1 on memory allocation failure,
 *                      -2 if reconciliation failed to converge after the
 *                         safety-net passes (caller treats as protocol abort).
 *
 * Algorithmic notes (worth pointing at during a defence):
 *
 *  1. Block size for pass 0 is k0 = max(1, round(0.73 / QBER)) -- the
 *     Cascade heuristic that yields ~1 error per block on average so most
 *     blocks have an odd (and therefore detectable) error count.
 *  2. The block size doubles each subsequent pass; this is the standard
 *     Brassard-Salvail schedule.
 *  3. Bob's bits are kept in *two* synchronised representations:
 *       - one master array `bob` in the caller's (original) index order;
 *       - one permuted view `b_perm` per pass, in that pass's shuffled
 *         order, used for O(1) contiguous parity reads.
 *     When back-prop flips a bit at original index `idx`, we walk every
 *     prior pass and patch its `b_perm[pos_of_index[idx]]` in O(1) per
 *     pass; this is what makes back-prop affordable.
 *  4. The BINCONF inner loop is the only place we recompute parities from
 *     scratch (over a halving range); even at full block size that range
 *     is small after the first halving, so the total cost is O(corrections
 *     * log(block_size)) parity operations per pass.
 *  5. We tally every parity bit the protocol would have announced on the
 *     public channel: one bit per block (announced at the start of every
 *     pass), plus one bit per BINCONF halving step. This number is what
 *     privacy amplification subtracts; it is *exact*, not estimated.
 *  6. Bit packing: bits are stored as one-byte-per-bit (uint8 with values
 *     0 or 1). This is wasteful in memory but trivially correct; for QKD
 *     post-processing sizes (tens of thousands of bits) the memory is not
 *     a concern, and the per-bit XOR is one machine instruction either
 *     way. A bit-packed version would only help once you cross into the
 *     gigabit-per-block regime, which is out of scope here.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* --- 64-bit PCG RNG ---------------------------------------------------- *
 * We use a self-contained PCG (O'Neill 2014) so the C side does not depend
 * on libc rand() (which is awful) and does not need to call back into
 * Python for randomness. The seed is supplied by the caller; the Python
 * wrapper draws it from os.urandom() so the C side stays cryptographically
 * acceptable for the simulated channel's permutations. (The randomness
 * here is *not* security-critical: it only chooses Cascade's block layout,
 * which both Alice and Bob would agree on over the authenticated classical
 * channel in a real deployment.) */

typedef struct {
    uint64_t state;
    uint64_t inc;
} pcg32_t;

static uint32_t pcg32(pcg32_t *r) {
    uint64_t oldstate = r->state;
    r->state = oldstate * 6364136223846793005ULL + (r->inc | 1);
    uint32_t xorshifted = (uint32_t)(((oldstate >> 18u) ^ oldstate) >> 27u);
    uint32_t rot = (uint32_t)(oldstate >> 59u);
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

static void pcg32_init(pcg32_t *r, uint64_t seed) {
    r->state = 0;
    r->inc = (seed << 1u) | 1u;
    pcg32(r);
    r->state += seed;
    pcg32(r);
}

/* Fisher-Yates shuffle of an int32_t array using the PCG above. */
static void shuffle_int32(int32_t *arr, int32_t n, pcg32_t *r) {
    for (int32_t i = n - 1; i > 0; --i) {
        /* Unbiased index in [0, i] via rejection sampling. */
        uint32_t bound = (uint32_t)(i + 1);
        uint32_t limit = (uint32_t)(-bound) % bound;
        uint32_t x;
        do { x = pcg32(r); } while (x < limit);
        int32_t j = (int32_t)(x % bound);
        int32_t tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

/* --- Per-pass bookkeeping --------------------------------------------- *
 * Mirrors qkd/reconciliation.py's _PassState dataclass: for every pass we
 * remember the permutation, its inverse, the start/end of each block, and
 * the per-block parity Alice announced. The materialised permuted Alice
 * and Bob views let parity reads be contiguous (a tight inner loop with
 * good cache behaviour). */

typedef struct {
    int32_t  *indices;          /* len n: original index at each shuffled pos */
    int32_t  *pos_of_index;     /* len n: inverse permutation */
    int32_t  *block_starts;     /* len num_blocks: start of each block */
    int32_t  *block_ends;       /* len num_blocks: end of each block */
    int32_t  *block_of_pos;     /* len n: block index per shuffled position */
    uint8_t  *a_perm;           /* len n: alice in shuffled order (immutable) */
    uint8_t  *b_perm;           /* len n: bob in shuffled order (live) */
    uint8_t  *block_parity_a;   /* len num_blocks: Alice's parity per block */
    int32_t   num_blocks;
} pass_state_t;

static void pass_state_free(pass_state_t *s) {
    if (!s) return;
    free(s->indices); free(s->pos_of_index);
    free(s->block_starts); free(s->block_ends);
    free(s->block_of_pos);
    free(s->a_perm); free(s->b_perm);
    free(s->block_parity_a);
}

/* Allocate and populate one pass's bookkeeping. The permutation arr is
 * COPIED in (so the caller may reuse / re-shuffle its working buffer). */
static int pass_state_init(pass_state_t *s, const uint8_t *alice,
                            const uint8_t *bob, const int32_t *perm,
                            int32_t n, int32_t block_size) {
    int32_t num_blocks = (n + block_size - 1) / block_size;
    s->num_blocks = num_blocks;
    s->indices = (int32_t*)malloc((size_t)n * sizeof(int32_t));
    s->pos_of_index = (int32_t*)malloc((size_t)n * sizeof(int32_t));
    s->block_starts = (int32_t*)malloc((size_t)num_blocks * sizeof(int32_t));
    s->block_ends = (int32_t*)malloc((size_t)num_blocks * sizeof(int32_t));
    s->block_of_pos = (int32_t*)malloc((size_t)n * sizeof(int32_t));
    s->a_perm = (uint8_t*)malloc((size_t)n);
    s->b_perm = (uint8_t*)malloc((size_t)n);
    s->block_parity_a = (uint8_t*)malloc((size_t)num_blocks);
    if (!s->indices || !s->pos_of_index || !s->block_starts ||
        !s->block_ends || !s->block_of_pos || !s->a_perm || !s->b_perm ||
        !s->block_parity_a) {
        pass_state_free(s);
        return -1;
    }
    memcpy(s->indices, perm, (size_t)n * sizeof(int32_t));
    for (int32_t sp = 0; sp < n; ++sp) {
        s->pos_of_index[perm[sp]] = sp;
        s->a_perm[sp] = alice[perm[sp]];
        s->b_perm[sp] = bob[perm[sp]];
    }
    for (int32_t b = 0; b < num_blocks; ++b) {
        int32_t start = b * block_size;
        int32_t end = start + block_size;
        if (end > n) end = n;
        s->block_starts[b] = start;
        s->block_ends[b] = end;
        uint8_t p = 0;
        for (int32_t sp = start; sp < end; ++sp) {
            p ^= s->a_perm[sp];
            s->block_of_pos[sp] = b;
        }
        s->block_parity_a[b] = p;
    }
    return 0;
}

static inline uint8_t array_parity(const uint8_t *arr, int32_t start, int32_t end) {
    uint8_t p = 0;
    for (int32_t i = start; i < end; ++i) p ^= arr[i];
    return p;
}

/* BINCONF: locate the single odd-parity error in arr[start:end].
 *
 * On entry: alice_perm and bob_perm differ in parity on the given range
 * (this is what flagged the block in the first place). We binary-search
 * the half that still has parity mismatch, counting one parity-bit per
 * halving step in *leaked_out, until we narrow to a single position.
 *
 * Returns the *original* (un-permuted) index of the differing bit. */
static int32_t binconf(const pass_state_t *s, int32_t start, int32_t end,
                       uint64_t *leaked_out) {
    while (end - start > 1) {
        int32_t mid = (start + end) / 2;
        uint8_t a_left = array_parity(s->a_perm, start, mid);
        uint8_t b_left = array_parity(s->b_perm, start, mid);
        (*leaked_out)++;
        if (a_left != b_left) end = mid;
        else                  start = mid;
    }
    return s->indices[start];
}

/* --- Main entry point: cascade_reconcile ----------------------------- */

int cascade_reconcile(
        uint8_t *alice, uint8_t *bob, int32_t n,
        double qber, int32_t passes, uint64_t seed,
        int32_t *out_corrected, uint64_t *out_leaked) {

    *out_corrected = 0;
    *out_leaked = 0;
    if (n == 0) return 0;

    /* Cascade-prescribed initial block size: ~0.73/QBER on average yields
     * one error per block. Clamp very low QBER so we never divide by zero
     * and never demand a block bigger than n. */
    double eff_q = qber < 1e-3 ? 1e-3 : qber;
    int32_t block_size = (int32_t)(0.73 / eff_q + 0.5);
    if (block_size < 1) block_size = 1;
    if (block_size > n) block_size = n;

    pcg32_t rng;
    pcg32_init(&rng, seed);

    /* Working permutation buffer, freshly shuffled each pass. The identity
     * permutation makes pass 0's "shuffle" a no-op (matches the Python
     * reference implementation's behaviour). */
    int32_t *perm = (int32_t*)malloc((size_t)n * sizeof(int32_t));
    if (!perm) return -1;
    for (int32_t i = 0; i < n; ++i) perm[i] = i;

    /* Generous upper bound on the number of passes we may ever run:
     * `passes` scheduled + 16 safety-net rounds. Each pass keeps a
     * pass_state_t; back-prop walks the whole history. */
    int32_t max_passes = passes + 16;
    pass_state_t *history = (pass_state_t*)calloc((size_t)max_passes,
                                                   sizeof(pass_state_t));
    if (!history) { free(perm); return -1; }
    int32_t history_len = 0;

    /* Back-prop worklist (visited via stack). Sized to n: an error fix may
     * in theory enqueue another error per prior pass, but in practice the
     * stack depth stays tiny; n is a safe upper bound. */
    int32_t *worklist = (int32_t*)malloc((size_t)n * sizeof(int32_t));
    if (!worklist) {
        free(perm);
        for (int32_t i = 0; i < history_len; ++i) pass_state_free(&history[i]);
        free(history);
        return -1;
    }

    int ret = 0;

    /* Per-cascade "touched" bitmap. Without it, a back-prop step can push
     * the same index repeatedly: when a prior block has a single error AND
     * that error is the same bit we just flipped (the trigger), BINCONF in
     * that prior returns the same index, which we re-push and re-flip,
     * undoing the fix. The pathological loop is bounded by spin_guard but
     * leaves corrected bogusly inflated. With `touched`, we flip each bit
     * at most once per FIX_VIA_BACKPROP invocation -- if back-prop tries
     * to re-touch it, we ignore the push. (Resetting between invocations
     * is correct: a later BINCONF in the OUTER pass loop is allowed to
     * re-touch the same bit if it genuinely needs another fix; the abuse
     * we are preventing is within a single cascade chain.) */
    uint8_t *touched = (uint8_t*)calloc((size_t)n, 1);
    if (!touched) {
        free(perm); free(worklist);
        for (int32_t i = 0; i < history_len; ++i) pass_state_free(&history[i]);
        free(history);
        return -1;
    }

    /* Inner helper: flip Bob's bit at original index `idx` AND update every
     * prior pass's permuted view in O(history_len). Then check each prior
     * pass's containing block: if its Bob parity now differs from Alice's
     * (cached at setup) a new odd-error block is exposed -- BINCONF it
     * and enqueue the new error for further cascading. */
    #define FIX_VIA_BACKPROP(start_idx) do {                                  \
        int32_t wl_top = 0;                                                   \
        memset(touched, 0, (size_t)n);                                        \
        touched[(start_idx)] = 1;                                             \
        worklist[wl_top++] = (start_idx);                                     \
        while (wl_top > 0) {                                                  \
            int32_t idx = worklist[--wl_top];                                 \
            bob[idx] ^= 1;                                                    \
            (*out_corrected)++;                                               \
            for (int32_t hi = 0; hi < history_len; ++hi) {                    \
                pass_state_t *prior = &history[hi];                           \
                int32_t sp = prior->pos_of_index[idx];                        \
                prior->b_perm[sp] ^= 1;                                       \
                int32_t b_idx = prior->block_of_pos[sp];                      \
                int32_t bs = prior->block_starts[b_idx];                      \
                int32_t be = prior->block_ends[b_idx];                        \
                uint8_t b_par = array_parity(prior->b_perm, bs, be);          \
                if (b_par != prior->block_parity_a[b_idx]) {                  \
                    int32_t new_idx = binconf(prior, bs, be, out_leaked);     \
                    if (!touched[new_idx] && wl_top < n) {                    \
                        touched[new_idx] = 1;                                 \
                        worklist[wl_top++] = new_idx;                         \
                    }                                                         \
                }                                                             \
            }                                                                 \
        }                                                                     \
    } while (0)

    /* --- Scheduled Cascade passes ------------------------------------- */
    for (int32_t p = 0; p < passes; ++p) {
        if (p > 0) shuffle_int32(perm, n, &rng);
        pass_state_t *state = &history[history_len++];
        if (pass_state_init(state, alice, bob, perm, n, block_size) != 0) {
            ret = -1; goto cleanup;
        }
        /* Announcement cost: one parity bit per block. */
        *out_leaked += (uint64_t)state->num_blocks;
        for (int32_t b = 0; b < state->num_blocks; ++b) {
            int32_t bs = state->block_starts[b];
            int32_t be = state->block_ends[b];
            /* Re-check after potential back-prop side-effects on b_perm. */
            uint8_t b_par = array_parity(state->b_perm, bs, be);
            if (b_par == state->block_parity_a[b]) continue;
            int32_t err_idx = binconf(state, bs, be, out_leaked);
            FIX_VIA_BACKPROP(err_idx);
        }
        /* Double the block size for the next pass, per the BS-94 schedule. */
        int64_t doubled = (int64_t)block_size * 2;
        block_size = (doubled > n) ? n : (int32_t)doubled;
    }

    /* --- Safety net: tight-block sweeps until convergence ------------- *
     * For QBER below the threshold this loop almost never runs; when it
     * does, small blocks (~14 bits at 5% QBER) make residual paired
     * errors split with high probability. The 16-iteration cap turns a
     * pathological case into a clean -2 abort instead of an infinite loop. */
    int32_t small_block = (int32_t)(0.73 / (eff_q < 0.05 ? 0.05 : eff_q) + 0.5);
    if (small_block < 1) small_block = 1;
    for (int32_t extra = 0; extra < 16; ++extra) {
        int32_t mismatch = 0;
        for (int32_t i = 0; i < n; ++i) {
            if (alice[i] != bob[i]) { mismatch = 1; break; }
        }
        if (!mismatch) break;
        if (history_len >= max_passes) { ret = -2; goto cleanup; }
        shuffle_int32(perm, n, &rng);
        pass_state_t *state = &history[history_len++];
        if (pass_state_init(state, alice, bob, perm, n, small_block) != 0) {
            ret = -1; goto cleanup;
        }
        *out_leaked += (uint64_t)state->num_blocks;
        for (int32_t b = 0; b < state->num_blocks; ++b) {
            int32_t bs = state->block_starts[b];
            int32_t be = state->block_ends[b];
            uint8_t b_par = array_parity(state->b_perm, bs, be);
            if (b_par == state->block_parity_a[b]) continue;
            int32_t err_idx = binconf(state, bs, be, out_leaked);
            FIX_VIA_BACKPROP(err_idx);
        }
    }

    /* Final convergence check: if Alice and Bob still differ, signal an
     * abort to the caller (Python wrapper raises QBERTooHighError). */
    for (int32_t i = 0; i < n; ++i) {
        if (alice[i] != bob[i]) { ret = -2; break; }
    }

cleanup:
    for (int32_t i = 0; i < history_len; ++i) pass_state_free(&history[i]);
    free(history);
    free(perm);
    free(worklist);
    free(touched);
    return ret;

    #undef FIX_VIA_BACKPROP
}
