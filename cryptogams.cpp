/*
 *  ovpn-dco-win OpenVPN protocol accelerator
 *
 *  Copyright (C) 2020-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 */

/*
 * Glue for the CRYPTOGAMS assembly (chacha-x86_64.asm, poly1305-x86_64.asm, both generated
 * from Andy Polyakov's perlasm and carrying its 3-clause BSD terms). Two things it needs
 * that a user-mode caller gets for free:
 *
 *   - a capability vector. The assembly picks its path by loading a qword from
 *     OPENSSL_ia32cap_P+4, so [1] must be CPUID(1).ECX and [2] CPUID(7,0).EBX.
 *   - the extended registers saved around every call. Windows does not preserve
 *     YMM/ZMM across a context switch for kernel code, so a vector path used without
 *     KeSaveExtendedProcessorState corrupts whatever else was using those registers.
 *     A bit is therefore only set when the processor has the feature and the kernel
 *     reports it will preserve the state.
 */

#include <ntddk.h>
#include <intrin.h>
#include "trace.h"
#include "cryptogams.h"

extern "C" {

unsigned int OPENSSL_ia32cap_P[4] = { 0 };

}   /* extern "C" */

/* how many data packets actually went down each encrypt path */
/* where TX packets go: to a worker, or encrypted inline on the drain thread */
volatile LONG64 g_TxWorkerPkts[8] = { 0 };

extern "C" {

/* from the assembly */
void ChaCha20_ctr32(unsigned char* out, const unsigned char* inp, size_t len,
                    const unsigned int key[8], const unsigned int counter[4]);
int  poly1305_init(void* ctx, const unsigned char key[16], void* func[2]);
void poly1305_blocks(void* ctx, const unsigned char* inp, size_t len, unsigned int padbit);
void poly1305_emit(void* ctx, unsigned char mac[16], const unsigned int nonce[4]);

}   /* extern "C" */

#ifndef XSTATE_MASK_AVX
#define XSTATE_MASK_AVX     (1ull << 2)
#endif
#ifndef XSTATE_MASK_AVX512
#define XSTATE_MASK_AVX512  ((1ull << 5) | (1ull << 6) | (1ull << 7))
#endif

/* exactly the state the dispatched code may touch; set at init, never narrowed later */
static ULONG64 g_XStateMask = XSTATE_MASK_LEGACY;
static BOOLEAN g_CryptogamsUsable = FALSE;
static BOOLEAN OvpnCryptogamsAeadSelfTest(VOID);

_Use_decl_annotations_
NTSTATUS
OvpnSimdGet(OVPN_SIMD_STATE* state)
{
    NTSTATUS status;

    state->Saved = FALSE;

    /* Ask for everything the selected path might touch. There is no narrower fallback:
       the assembly picks its path from the capability vector fixed at init, so saving
       less than it will clobber corrupts whoever we interrupted. Fail and let the
       caller use CNG for this packet instead. */
    status = KeSaveExtendedProcessorState(g_XStateMask, &state->XState);
    if (NT_SUCCESS(status)) {
        state->Saved = TRUE;
    }
    return status;
}

_Use_decl_annotations_
VOID
OvpnSimdPut(OVPN_SIMD_STATE* state)
{
    if (state->Saved) {
        KeRestoreExtendedProcessorState(&state->XState);
        state->Saved = FALSE;
    }
}

/*
 * Known-answer tests, run once at init. The references were produced by an independent
 * ChaCha20 and Poly1305 written against RFC 8439, not copied from the RFC's own vectors.
 * A vector path that faults or returns the wrong answer must not reach the data path.
 */
static BOOLEAN
OvpnCryptogamsSelfTest(VOID)
{
    static const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
    static const unsigned char ctr[16] = {
        0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x4a, 0x00,0x00,0x00,0x00 };
    static const char pt[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
        "the future, sunscreen would be it.";
    static const unsigned char wantCipher[16] = {
        0x5c,0x90,0x83,0x8d,0xb4,0x48,0x79,0x74,0x3e,0x6b,0xfd,0x58,0xc6,0x4e,0x05,0xa8 };
    static const unsigned char wantMac[16] = {
        0x63,0xea,0x8c,0x09,0x60,0x65,0x2e,0x59,0x97,0xf2,0x59,0xab,0x33,0x73,0x56,0x8a };

    unsigned char cipher[sizeof(pt)];
    unsigned char mac[16];
    unsigned char msg[1392];
    __declspec(align(64)) unsigned char ctx[320];
    void* fn[2] = { NULL, NULL };
    OVPN_SIMD_STATE simd;
    BOOLEAN ok;

    if (!NT_SUCCESS(OvpnSimdGet(&simd))) {
        LOG_ERROR("cryptogams: cannot save extended processor state");
        return FALSE;
    }

    ChaCha20_ctr32(cipher, (const unsigned char*)pt, sizeof(pt) - 1,
                   (const unsigned int*)key, (const unsigned int*)ctr);

    RtlFillMemory(msg, sizeof(msg), 0xA5);
    RtlZeroMemory(ctx, sizeof(ctx));
    if (poly1305_init(ctx, key, fn) && (fn[0] != NULL) && (fn[1] != NULL)) {
        ((void (*)(void*, const unsigned char*, size_t, unsigned int))fn[0])(ctx, msg, sizeof(msg), 1);
        ((void (*)(void*, unsigned char*, const unsigned int*))fn[1])(ctx, mac, (const unsigned int*)(key + 16));
    }
    else {
        poly1305_blocks(ctx, msg, sizeof(msg), 1);
        poly1305_emit(ctx, mac, (const unsigned int*)(key + 16));
    }

    OvpnSimdPut(&simd);

    ok = (RtlCompareMemory(cipher, wantCipher, 16) == 16) &&
         (RtlCompareMemory(mac, wantMac, 16) == 16);
    return ok;
}

_Use_decl_annotations_
VOID
OvpnCryptogamsInit(VOID)
{
    int regs[4];
    ULONG64 enabled;
    int maxLeaf;

    __cpuid(regs, 0);
    maxLeaf = regs[0];

    __cpuid(regs, 1);
    OPENSSL_ia32cap_P[0] = (unsigned int)regs[3];   /* EDX */
    OPENSSL_ia32cap_P[1] = (unsigned int)regs[2];   /* ECX */

    if (maxLeaf >= 7) {
        __cpuidex(regs, 7, 0);
        OPENSSL_ia32cap_P[2] = (unsigned int)regs[1];   /* EBX */
        OPENSSL_ia32cap_P[3] = (unsigned int)regs[2];   /* ECX */
    }

    /* what the kernel will actually preserve for us, not merely what the CPU has */
    enabled = RtlGetEnabledExtendedFeatures(MAXULONG64);

    if ((enabled & XSTATE_MASK_AVX) == 0) {
        OPENSSL_ia32cap_P[1] &= ~(1u << 28);        /* AVX  */
        OPENSSL_ia32cap_P[2] &= ~(1u << 5);         /* AVX2 */
    }
    if ((enabled & XSTATE_MASK_AVX512) != XSTATE_MASK_AVX512) {
        OPENSSL_ia32cap_P[2] &= ~((1u << 16) | (1u << 17) | (1u << 21) |
                                  (1u << 26) | (1u << 27) | (1u << 28) |
                                  (1u << 30) | (1u << 31));
    }

    g_XStateMask = XSTATE_MASK_LEGACY;
    if (OPENSSL_ia32cap_P[1] & (1u << 28)) {
        g_XStateMask |= XSTATE_MASK_AVX;
    }
    if (OPENSSL_ia32cap_P[2] & (1u << 16)) {
        g_XStateMask |= XSTATE_MASK_AVX512;
    }

    g_CryptogamsUsable = OvpnCryptogamsSelfTest() && OvpnCryptogamsAeadSelfTest();

    LOG_INFO("cryptogams init",
             TraceLoggingValue(OPENSSL_ia32cap_P[1], "cap1"),
             TraceLoggingValue(OPENSSL_ia32cap_P[2], "cap2"),
             TraceLoggingValue((UINT32)(enabled & 0xffffffff), "xstate"),
             TraceLoggingValue(g_CryptogamsUsable ? 1 : 0, "selftest"));
}

_Use_decl_annotations_
BOOLEAN
OvpnCryptogamsUsable(VOID)
{
    return g_CryptogamsUsable;
}

/*
 * RFC 8439 AEAD. Every Poly1305 input is a whole 16-byte block with the 2^128 bit set, so
 * the partial tail and the AAD are copied into a zeroed block rather than passed directly -
 * poly1305_blocks only takes whole blocks.
 */
typedef void (*OvpnPolyBlocks)(void*, const unsigned char*, size_t, unsigned int);
typedef void (*OvpnPolyEmit)(void*, unsigned char*, const unsigned int*);

static VOID
OvpnPolyRun(_In_reads_(32) const UCHAR* polyKey,
            _In_reads_(aadLen) const UCHAR* aad, SIZE_T aadLen,
            _In_reads_(ctLen) const UCHAR* ct, SIZE_T ctLen,
            _Out_writes_(16) UCHAR* tag)
{
    __declspec(align(64)) UCHAR ctx[320];
    UCHAR block[16];
    void* fn[2] = { NULL, NULL };
    OvpnPolyBlocks blocks = poly1305_blocks;
    OvpnPolyEmit emit = poly1305_emit;
    SIZE_T whole;

    RtlZeroMemory(ctx, sizeof(ctx));
    if (poly1305_init(ctx, polyKey, fn) && (fn[0] != NULL) && (fn[1] != NULL)) {
        blocks = (OvpnPolyBlocks)fn[0];
        emit = (OvpnPolyEmit)fn[1];
    }

    if (aadLen != 0) {
        whole = aadLen & ~(SIZE_T)15;
        if (whole != 0) {
            blocks(ctx, aad, whole, 1);
        }
        if (aadLen != whole) {
            RtlZeroMemory(block, sizeof(block));
            RtlCopyMemory(block, aad + whole, aadLen - whole);
            blocks(ctx, block, sizeof(block), 1);
        }
    }

    if (ctLen != 0) {
        whole = ctLen & ~(SIZE_T)15;
        if (whole != 0) {
            blocks(ctx, ct, whole, 1);
        }
        if (ctLen != whole) {
            RtlZeroMemory(block, sizeof(block));
            RtlCopyMemory(block, ct + whole, ctLen - whole);
            blocks(ctx, block, sizeof(block), 1);
        }
    }

    /* lengths, little endian, as one more full block */
    RtlZeroMemory(block, sizeof(block));
    *(UINT64 UNALIGNED*)(block) = (UINT64)aadLen;
    *(UINT64 UNALIGNED*)(block + 8) = (UINT64)ctLen;
    blocks(ctx, block, sizeof(block), 1);

    emit(ctx, tag, (const unsigned int*)(polyKey + 16));
}

/* counter[0] is the block counter, counter[1..3] the nonce */
static VOID
OvpnChaChaCounter(_Out_writes_(4) unsigned int* counter, _In_reads_(12) const UCHAR* nonce,
                  unsigned int block)
{
    counter[0] = block;
    RtlCopyMemory(counter + 1, nonce, 12);
}

/* the work, with the extended state already saved by the caller */
static VOID
OvpnChaChaPolyEncryptInner(const UCHAR* key, const UCHAR* nonce,
                           const UCHAR* aad, SIZE_T aadLen,
                           UCHAR* data, SIZE_T dataLen, UCHAR* tag)
{
    unsigned int counter[4];
    UCHAR polyKey[32];

    /* the one-time Poly1305 key is the first 32 bytes of the keystream at counter 0 */
    RtlZeroMemory(polyKey, sizeof(polyKey));
    OvpnChaChaCounter(counter, nonce, 0);
    ChaCha20_ctr32(polyKey, polyKey, sizeof(polyKey), (const unsigned int*)key, counter);

    OvpnChaChaCounter(counter, nonce, 1);
    ChaCha20_ctr32(data, data, dataLen, (const unsigned int*)key, counter);

    OvpnPolyRun(polyKey, aad, aadLen, data, dataLen, tag);
    RtlSecureZeroMemory(polyKey, sizeof(polyKey));
}

_Use_decl_annotations_
NTSTATUS
OvpnChaChaPolyEncrypt(const UCHAR* key, const UCHAR* nonce,
                      const UCHAR* aad, SIZE_T aadLen,
                      UCHAR* data, SIZE_T dataLen, UCHAR* tag)
{
    OVPN_SIMD_STATE simd;
    NTSTATUS status = OvpnSimdGet(&simd);

    if (!NT_SUCCESS(status)) {
        return status;
    }
    OvpnChaChaPolyEncryptInner(key, nonce, aad, aadLen, data, dataLen, tag);
    OvpnSimdPut(&simd);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnChaChaPolyDecrypt(const UCHAR* key, const UCHAR* nonce,
                      const UCHAR* aad, SIZE_T aadLen,
                      UCHAR* data, SIZE_T dataLen, const UCHAR* tag)
{
    OVPN_SIMD_STATE simd;
    unsigned int counter[4];
    UCHAR polyKey[32];
    UCHAR expect[16];
    NTSTATUS status;
    SIZE_T same;

    status = OvpnSimdGet(&simd);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(polyKey, sizeof(polyKey));
    OvpnChaChaCounter(counter, nonce, 0);
    ChaCha20_ctr32(polyKey, polyKey, sizeof(polyKey), (const unsigned int*)key, counter);

    /* authenticate the ciphertext before it is turned back into plaintext */
    OvpnPolyRun(polyKey, aad, aadLen, data, dataLen, expect);
    same = RtlCompareMemory(expect, tag, sizeof(expect));

    if (same == sizeof(expect)) {
        OvpnChaChaCounter(counter, nonce, 1);
        ChaCha20_ctr32(data, data, dataLen, (const unsigned int*)key, counter);
    }

    OvpnSimdPut(&simd);
    RtlSecureZeroMemory(polyKey, sizeof(polyKey));
    RtlSecureZeroMemory(expect, sizeof(expect));

    return (same == sizeof(expect)) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
}

/*
 * The AEAD as a whole, with AAD and a payload that is not a multiple of 16 - the two things
 * the primitive tests above do not exercise. Reference computed independently from RFC 8439.
 */
static BOOLEAN
OvpnCryptogamsAeadSelfTest(VOID)
{
    static const UCHAR key[32] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
    static const UCHAR nonce[12] = { 0,1,2,3,4,5,6,7,8,9,10,11 };
    static const UCHAR aad[8] = { 0x40,0x00,0x00,0x01,0x00,0x00,0x00,0x07 };
    static const UCHAR wantCt[16] = {
        0x89,0xfa,0x0a,0x03,0x2d,0x12,0xa3,0x47,0xbf,0x8a,0x35,0xf8,0x94,0x10,0x00,0x6c };
    static const UCHAR wantTag[16] = {
        0xde,0xec,0xb3,0x3b,0xab,0xbd,0xfd,0xde,0xfa,0xc4,0x55,0x62,0x16,0x8e,0x37,0x81 };

    UCHAR buf[565];
    UCHAR tag[16];
    SIZE_T i;
    BOOLEAN ok;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (UCHAR)(i & 0xff);
    }

    if (!NT_SUCCESS(OvpnChaChaPolyEncrypt(key, nonce, aad, sizeof(aad),
                                          buf, sizeof(buf), tag))) {
        return FALSE;
    }
    ok = (RtlCompareMemory(buf, wantCt, 16) == 16) &&
         (RtlCompareMemory(tag, wantTag, 16) == 16);
    if (!ok) {
        return FALSE;
    }

    /* and it must come back, and must reject a corrupted tag */
    if (!NT_SUCCESS(OvpnChaChaPolyDecrypt(key, nonce, aad, sizeof(aad),
                                          buf, sizeof(buf), tag))) {
        return FALSE;
    }
    for (i = 0; i < sizeof(buf); i++) {
        if (buf[i] != (UCHAR)(i & 0xff)) {
            return FALSE;
        }
    }
    tag[0] ^= 1;
    if (OvpnChaChaPolyDecrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), tag)
        != STATUS_INVALID_SIGNATURE) {
        return FALSE;
    }
    return TRUE;
}

