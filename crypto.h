/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2023 Rubicon Communications LLC (Netgate)
 *
 *  Author:	Lev Stipakov <lev@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include <ntddk.h>
#include <bcrypt.h>

#include "crypto_epoch.h"
#include "pktid.h"
#include "uapi\ovpn-dco.h"
#include "socket.h"

struct OvpnPeerContext;

#define OVPN_DATA_V2_LEN 4
#define AEAD_AUTH_TAG_LEN 16

#if DBG
// Checked-build test hook, set from the driver's Parameters key in
// DriverEntry. Caps the AEAD usage limit of every new key so epochs rotate
// every few packets. It can only shorten a key's life, never extend it.
extern ULONG g_OvpnTestAeadUsageLimit;
#endif

 // packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte
#define OVPN_OP_DATA_V2 9
#define OVPN_KEY_ID_MASK 0x07
#define OVPN_OPCODE_SHIFT 3
#define OVPN_PEER_ID_MASK 0x00FFFFFF

_Function_class_(OVPN_CRYPTO_ENCRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_ENCRYPT(_Inout_ OvpnCryptoTxState* tx, _In_ UCHAR* buf, _In_ SIZE_T len, _In_ OvpnCryptoOptions* opts);
typedef OVPN_CRYPTO_ENCRYPT* POVPN_CRYPTO_ENCRYPT;

_Function_class_(OVPN_CRYPTO_DECRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_DECRYPT(_Inout_ OvpnCryptoRxState* rx, _In_ UCHAR* bufIn, _In_ SIZE_T len, _In_ UCHAR* bufOut, _In_ OvpnCryptoOptions* opts, _Out_ UINT16* sendEpoch);
typedef OVPN_CRYPTO_DECRYPT* POVPN_CRYPTO_DECRYPT;

struct OvpnCryptoPacketLayout
{
    ULONG FrontLen;
    ULONG TailLen;
};

// Crypto state is split by traffic direction: OvpnCryptoTxContext under
// peer->TxLock, OvpnCryptoRxContext under peer->RxLock. Neither lock is ever
// taken while holding the other.

// Everything the TX path needs. Guarded by peer->TxLock.
struct OvpnCryptoTxContext
{
    OvpnCryptoTxState Primary;
    OvpnCryptoTxState Secondary;

    POVPN_CRYPTO_ENCRYPT Encrypt;
    OvpnCryptoOptions Options;
    OvpnCryptoPacketLayout Layout;
};

// Everything the RX path needs. Guarded by peer->RxLock.
struct OvpnCryptoRxContext
{
    OvpnCryptoRxState Primary;
    OvpnCryptoRxState Secondary;

    POVPN_CRYPTO_DECRYPT Decrypt;
    OvpnCryptoOptions Options;
    OvpnCryptoPacketLayout Layout;
};

struct OvpnCryptoContext
{
    OvpnCryptoTxContext Tx;
    OvpnCryptoRxContext Rx;
};

// Encrypts in place with the primary key. Caller holds peer->TxLock.
_Must_inspect_result_
_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
OvpnCryptoEncrypt(_Inout_ OvpnCryptoTxContext* tx, _Inout_ PUCHAR buf, _In_ SIZE_T len);

// Decrypts with the key that has keyId. Caller holds peer->RxLock. A non-zero
// *sendEpoch asks the caller to call OvpnCryptoFollowPeerEpoch under TxLock
// once RxLock is released.
_Must_inspect_result_
_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
OvpnCryptoDecrypt(_Inout_ OvpnCryptoRxContext* rx, _In_ UCHAR keyId, _In_reads_bytes_(len) PUCHAR cipherText, _In_ SIZE_T len, _Inout_updates_bytes_(len) PUCHAR plainText, _Out_ UINT16* sendEpoch);

// Moves the send key with keyId forward to epoch. Caller holds peer->TxLock.
_IRQL_requires_(DISPATCH_LEVEL)
VOID
OvpnCryptoFollowPeerEpoch(_Inout_ OvpnCryptoTxContext* tx, _In_ UCHAR keyId, _In_ UINT16 epoch);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnCryptoInitAlgHandles(_Outptr_ BCRYPT_ALG_HANDLE* aesAlgHandle, _Outptr_ BCRYPT_ALG_HANDLE* chachaAlgHandle, _Outptr_ BCRYPT_ALG_HANDLE* hkdfAlgHandle);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
OvpnCryptoUninitAlgHandles(_In_ BCRYPT_ALG_HANDLE aesAlgHandle, BCRYPT_ALG_HANDLE chachaAlgHandle, BCRYPT_ALG_HANDLE hkdfAlgHandle);

VOID
OvpnCryptoUninit(_In_ OvpnCryptoContext* cryptoContext);

_Must_inspect_result_
NTSTATUS
OvpnCryptoNewKey(_Inout_ OvpnPeerContext* peer, _In_ POVPN_CRYPTO_DATA_V2 cryptoData, _In_opt_ BCRYPT_ALG_HANDLE algHandle, _In_opt_ BCRYPT_ALG_HANDLE hkdfAlgHandle);

VOID
OvpnCryptoSwapKeys(_Inout_ OvpnPeerContext* peer);

static inline
UCHAR
OvpnCryptoKeyIdExtract(UCHAR op)
{
    return op & OVPN_KEY_ID_MASK;
}

static inline
UCHAR OvpnCryptoOpcodeExtract(UCHAR op)
{
    return op >> OVPN_OPCODE_SHIFT;
}

static inline
UINT64
OvpnCryptoAeadUsageLimit(OVPN_CIPHER_ALG alg)
{
    switch (alg)
    {
    case OVPN_CIPHER_ALG_NONE:
        return 0;

    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
        return 0;

    default:
        return (1ull << 36) - 1; // limit for AES-GCM
    }
}
