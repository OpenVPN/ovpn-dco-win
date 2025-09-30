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

#include "pktid.h"
#include "uapi\ovpn-dco.h"
#include "socket.h"

struct OvpnPeerContext;

#define OVPN_DATA_V2_LEN 4
#define AEAD_AUTH_TAG_LEN 16

#define AEAD_LIMIT_BLOCKSIZE 16

// The crypto helper uses this failure status to indicate that the caller must
// retry the operation while holding the peer spinlock exclusively so key-slot
// mutation can proceed safely.
#define STATUS_OVPN_CRYPTO_RETRY ((NTSTATUS)0xC0E44001L)

 // packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte
#define OVPN_OP_DATA_V2 9
#define OVPN_KEY_ID_MASK 0x07
#define OVPN_OPCODE_SHIFT 3
#define OVPN_PEER_ID_MASK 0x00FFFFFF
#define PACKET_ID_EPOCH_MAX 0x0000FFFFFFFFFFFFull

#define FUTURE_EPOCH_KEYS_COUNT 16

struct OvpnCryptoKeyContext
{
    BCRYPT_KEY_HANDLE Key;
    UCHAR ImplicitIV[12];

    // number of plaintext blocks encrypted using this key
    UINT64 PlaintextBlocks;
    UINT16 Epoch;
};

struct OvpnCryptoEpochKey
{
    UCHAR EpochKey[32];
    UINT16 Epoch;
};

struct OvpnCryptoKeySlot
{
    OvpnCryptoKeyContext Encrypt;
    OvpnCryptoKeyContext Decrypt;

    // last epoch key used for generating current send data keys
    OvpnCryptoEpochKey EpochKeySend;

    // epoch key used for the highest receive epoch keys
    OvpnCryptoEpochKey EpochKeyRecv;

    UCHAR KeyId;
    INT32 PeerId;

    OvpnPktidXmit PktidXmit;
    OvpnPktidRecv PktidRecv;

    // future epoch data keys for decryption
    OvpnCryptoKeyContext FutureEpochKeys[FUTURE_EPOCH_KEYS_COUNT];

    OvpnPktidRecv PktidRecvRetiring;
    OvpnCryptoKeyContext RetiringEpochDataReceiveKey;
};

struct OvpnCryptoOptions {
    // Limit for AEAD cipher, sum of packets + blocks. Will switch to the new epoch when reached.
    UINT64 AeadUsageLimit;

    BOOLEAN UseEpoch;

    UCHAR KeyLen;

    BCRYPT_ALG_HANDLE HkdfAlgHandle;
    BCRYPT_ALG_HANDLE AeadAlgHangle;
};

_Function_class_(OVPN_CRYPTO_ENCRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_ENCRYPT(_In_ OvpnCryptoKeySlot* keySlot, _In_ UCHAR* buf, _In_ SIZE_T len, _In_ OvpnCryptoOptions* opts, BOOLEAN allowRekey);
typedef OVPN_CRYPTO_ENCRYPT* POVPN_CRYPTO_ENCRYPT;

_Function_class_(OVPN_CRYPTO_DECRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_DECRYPT(_In_ OvpnCryptoKeySlot* keySlot, _In_ UCHAR* bufIn, _In_ SIZE_T len, _In_ UCHAR* bufOut, _In_ OvpnCryptoOptions* opts, BOOLEAN allowRekey);
typedef OVPN_CRYPTO_DECRYPT* POVPN_CRYPTO_DECRYPT;

struct OvpnCryptoPacketLayout
{
    ULONG FrontLen;
    ULONG TailLen;
};

struct OvpnCryptoContext
{
    OvpnCryptoKeySlot Primary;
    OvpnCryptoKeySlot Secondary;

    POVPN_CRYPTO_ENCRYPT Encrypt;
    POVPN_CRYPTO_DECRYPT Decrypt;

    OvpnCryptoOptions Options;
    OvpnCryptoPacketLayout Layout;
};


VOID
OvpnCryptoDescribePacketLayout(_In_ const OvpnCryptoContext* cryptoContext, _Out_ OvpnCryptoPacketLayout* layout);

typedef
NTSTATUS
OVPN_CRYPTO_RETRY_ROUTINE(_In_ OvpnCryptoContext* cryptoContext, _In_ BOOLEAN allowRekey, _Inout_opt_ PVOID context);
typedef OVPN_CRYPTO_RETRY_ROUTINE* POVPN_CRYPTO_RETRY_ROUTINE;

struct OvpnCryptoEncryptParams
{
    PUCHAR Buffer;
    SIZE_T Length;
};

struct OvpnCryptoDecryptParams
{
    UCHAR KeyId;
    PUCHAR CipherText;
    SIZE_T Length;
    PUCHAR PlainText;
};

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
OvpnCryptoCallWithRetry(
    _In_ OvpnPeerContext* peer,
    _In_ BOOLEAN atDpcLevel,
    _Inout_opt_ PBOOLEAN exclusive,
    _Inout_opt_ PKIRQL kirql,
    _In_ POVPN_CRYPTO_RETRY_ROUTINE routine,
    _Inout_opt_ PVOID context);

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
OvpnCryptoInvokeEncrypt(
    _In_ OvpnCryptoContext* cryptoContext,
    _In_ BOOLEAN allowRekey,
    _Inout_opt_ PVOID context);

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
OvpnCryptoInvokeDecrypt(
    _In_ OvpnCryptoContext* cryptoContext,
    _In_ BOOLEAN allowRekey,
    _Inout_opt_ PVOID context);

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
OvpnCryptoNewKey(_In_ OvpnCryptoContext* cryptoContext, _In_ POVPN_CRYPTO_DATA_V2 cryptoData, _In_opt_ BCRYPT_ALG_HANDLE algHandle, _In_opt_ BCRYPT_ALG_HANDLE hkdfAlgHandle);

_Must_inspect_result_
OvpnCryptoKeySlot*
OvpnCryptoKeySlotFromKeyId(_In_ OvpnCryptoContext* cryptoContext, unsigned int keyId);

VOID
OvpnCryptoSwapKeys(_In_ OvpnCryptoContext* cryptoContext);

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
BOOLEAN
OvpnCryptoAeadUsageLimitReached(UINT64 limit, UINT64 plaintextBlocks, UINT64 highestPid)
{
    /* This is the  q + s <=  p^(1/2) * 2^(129/2) - 1 calculation where
     * q is the number of protected messages (highest_pid)
     * s Total plaintext length in all messages (in blocks) */
    return ((limit > 0) && (plaintextBlocks + highestPid) > limit);
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
