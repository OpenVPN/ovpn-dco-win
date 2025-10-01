/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2025- OpenVPN Inc <sales@openvpn.net>
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

#if defined(_KERNEL_MODE)
#include <ntddk.h>
#include <ntstrsafe.h>
#include "trace.h"
#else
#define WIN32_NO_STATUS     // keep windows.h from redefining STATUS_*
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>       // exposes STATUS_SUCCESS, NT_SUCCESS, etc.
#include <strsafe.h>
#define RtlStringCbLengthA StringCbLengthA
#ifndef UINT16_MAX
#define UINT16_MAX 0xFFFF
#endif
#endif

#include <bcrypt.h>

#include "pktid.h"

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

struct OvpnCryptoKeyParameters
{
    UCHAR Cipher[32];
    UCHAR IV[12];
    BCRYPT_KEY_HANDLE KeyHandle;
    UINT16 Epoch;
};

struct OvpnCryptoOptions {
    // Limit for AEAD cipher, sum of packets + blocks. Will switch to the new epoch when reached.
    UINT64 AeadUsageLimit;

    BOOLEAN UseEpoch;

    UCHAR KeyLen;

    BCRYPT_ALG_HANDLE HkdfAlgHandle;
    BCRYPT_ALG_HANDLE AeadAlgHangle;
};

NTSTATUS OvpnCryptoExpandLabel(
    BCRYPT_ALG_HANDLE hkdfAlg,
    _In_reads_bytes_(32) const UCHAR* E_i,       // PRK (32 bytes for SHA-256)
    _In_ USHORT outLen,                          // bytes to derive
    _In_z_ const char* label,                    // "data_key" / "data_iv" / "datakey upd"
    _Out_writes_bytes_(outLen) UCHAR* outBytes
);

_IRQL_requires_max_(PASSIVE_LEVEL)
static
NTSTATUS OvpnCryptoMakeLabel(
    _Out_writes_bytes_to_(cbOut, *pcbWritten) UCHAR* out,
    _In_ ULONG cbOut,
    _Out_ ULONG* pcbWritten,
    _In_ USHORT L,
    _In_z_ const char* label);

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

// Initialises data channel key/IV using the provided epoch key
VOID
OvpnCryptoEpochInitKey(OvpnCryptoKeyContext* ctx, OvpnCryptoEpochKey* epochKey, OvpnCryptoOptions* opts);

// Generates a data channel key/IV from the epoch key
NTSTATUS
OvpnCryptoEpochDataKeyDerive(OvpnCryptoKeyParameters* key, OvpnCryptoEpochKey* epochKey, BCRYPT_ALG_HANDLE hkdfAlgHandle, BCRYPT_ALG_HANDLE algHandle, UCHAR cipherSize);

VOID
OvpnCryptoEpochKeyIterate(OvpnCryptoEpochKey* epochKey, BCRYPT_ALG_HANDLE hkdfAlgHandle);
/**
 * Generates and fills the FutureEpochKeys with next valid future keys
 * using the epoch of the key in keySlot->EpochKeyRecv as starting point
 */
VOID
OvpnCryptoEpochGenerateFutureRecvKeys(OvpnCryptoKeySlot* keySlot, OvpnCryptoOptions* opts);

// This is called when the peer uses a new send key that is not the default key
VOID
OvpnCryptoEpochReplaceUpdateRecvKey(OvpnCryptoKeySlot* keySlot, UINT16 new_epoch, OvpnCryptoOptions* opts);

// retrieve decryption key context that matches the epoch
OvpnCryptoKeyContext*
OvpnCryptoEpochLookupDecryptKey(OvpnCryptoKeySlot* keySlot, UINT16 epoch);

VOID
OvpnCryptoMakeEpochNonce(UCHAR* epochIv, UINT64 packet_id_net, UCHAR* nonce);

// Updates the send key and keySlot->EpochKeySend to use the next epoch
VOID
OvpnCryptoEpochIterateSendKey(OvpnCryptoKeySlot* keySlot, OvpnCryptoOptions* opts);

VOID
OvpnCryptoEpochUninitSlot(OvpnCryptoKeySlot* slot);