/*
 *  ovpn-dco-win OpenVPN protocol accelerator
 *
 *  Copyright (C) 2020-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 */

#pragma once

#include <ntddk.h>

/* Saved extended registers for one span of vector code. Kernel code must bracket any use
   of YMM/ZMM with these, or the registers it clobbers belong to whoever was interrupted. */
typedef struct _OVPN_SIMD_STATE {
    XSTATE_SAVE XState;
    BOOLEAN Saved;
} OVPN_SIMD_STATE;

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
OvpnSimdGet(_Out_ OVPN_SIMD_STATE* state);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
OvpnSimdPut(_Inout_ OVPN_SIMD_STATE* state);

/* Fills the capability vector the assembly dispatches on and runs the self test. */
VOID
OvpnCryptogamsInit(VOID);

/* FALSE when the self test failed or the state could not be saved; callers must then
   stay on the CNG path. */
BOOLEAN
OvpnCryptogamsUsable(VOID);

/*
 * RFC 8439 ChaCha20-Poly1305 over the CRYPTOGAMS primitives. Same shape as the CNG call it
 * replaces: payload encrypted in place, tag written separately, AAD authenticated but not
 * encrypted. Callers must have checked OvpnCryptogamsUsable().
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
OvpnChaChaPolyEncrypt(_In_reads_(32) const UCHAR* key, _In_reads_(12) const UCHAR* nonce,
                      _In_reads_(aadLen) const UCHAR* aad, SIZE_T aadLen,
                      _Inout_updates_(dataLen) UCHAR* data, SIZE_T dataLen,
                      _Out_writes_(16) UCHAR* tag);

/* Returns STATUS_INVALID_SIGNATURE when the tag does not match; the payload is decrypted
   in place either way, so a caller must not use it unless this succeeded. */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
OvpnChaChaPolyDecrypt(_In_reads_(32) const UCHAR* key, _In_reads_(12) const UCHAR* nonce,
                      _In_reads_(aadLen) const UCHAR* aad, SIZE_T aadLen,
                      _Inout_updates_(dataLen) UCHAR* data, SIZE_T dataLen,
                      _In_reads_(16) const UCHAR* tag);
