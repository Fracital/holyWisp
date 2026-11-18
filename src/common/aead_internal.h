/*
 * src/common/aead_internal.h - the part of src/common/aead.c that tests reach past the contract
 * (holywisp/aead.h): which ChaCha20 and Poly1305 kernels run, so that one test binary holds
 * every kernel the target has to the same vectors, whatever CPU runs it. Nothing outside tests/
 * includes this.
 */
#ifndef HOLYWISP_COMMON_AEAD_INTERNAL_H
#define HOLYWISP_COMMON_AEAD_INTERNAL_H

// With on set, ChaCha20 and Poly1305 use their base kernels (four blocks in the compiler's
// generic vectors) from the next call on, on every thread; with on clear, the CPU chooses again
// (AVX2 on x86-64 when it has it). Returns 1 when this CPU has a kernel other than the base one,
// so that forcing the base changes what runs, and 0 when the base kernel is all there is. Not
// for use while another thread is sealing or opening: a call that is under way may use either.
int hw_aead_force_base_kernels(int on);

#endif
