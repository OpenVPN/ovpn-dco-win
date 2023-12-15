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

#define AEAD_CRYPTO_OVERHEAD 24 // 4 + 4 + 16 data_v2 + pktid + auth_tag
#define NONE_CRYPTO_OVERHEAD 8 // 4 + 4 data_v2 + pktid
#define OVPN_PKTID_LEN 4
#define OVPN_NONCE_TAIL_LEN 8
#define OVPN_DATA_V2_LEN 4
#define AEAD_AUTH_TAG_LEN 16
#define AES_BLOCK_SIZE 16
#define AES_GCM_NONCE_LEN 12

 // packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte
#define OVPN_OP_DATA_V2 9
#define OVPN_KEY_ID_MASK 0x07
#define OVPN_OPCODE_SHIFT 3

struct OvpnCryptoKeySlot
{
    BCRYPT_KEY_HANDLE EncKey;
    BCRYPT_KEY_HANDLE DecKey;

    UCHAR EncNonceTail[8];
    UCHAR DecNonceTail[8];

    UCHAR KeyId;
    INT32 PeerId;

    OvpnPktidXmit PktidXmit;
    OvpnPktidRecv PktidRecv;
};

_Function_class_(OVPN_CRYPTO_ENCRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_ENCRYPT(_In_ OvpnCryptoKeySlot* keySlot, _In_ UCHAR* buf, _In_ SIZE_T len);
typedef OVPN_CRYPTO_ENCRYPT* POVPN_CRYPTO_ENCRYPT;

_Function_class_(OVPN_CRYPTO_DECRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_DECRYPT(_In_ OvpnCryptoKeySlot* keySlot, _In_ UCHAR* bufIn, _In_ SIZE_T len, _In_ UCHAR* bufOut);
typedef OVPN_CRYPTO_DECRYPT* POVPN_CRYPTO_DECRYPT;

struct OvpnCryptoContext
{
    OvpnCryptoKeySlot Primary;
    OvpnCryptoKeySlot Secondary;

    POVPN_CRYPTO_ENCRYPT Encrypt;
    POVPN_CRYPTO_DECRYPT Decrypt;

    SIZE_T CryptoOverhead;
};

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnCryptoInitAlgHandles(_Outptr_ BCRYPT_ALG_HANDLE* aesAlgHandle, _Outptr_ BCRYPT_ALG_HANDLE* chachaAlgHandle);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
OvpnCryptoUninitAlgHandles(_In_ BCRYPT_ALG_HANDLE aesAlgHandle, BCRYPT_ALG_HANDLE chachaAlgHandle);

VOID
OvpnCryptoUninit(_In_ OvpnCryptoContext* cryptoContext);

_Must_inspect_result_
NTSTATUS
OvpnCryptoNewKey(_In_ OvpnCryptoContext* cryptoContext, _In_ POVPN_CRYPTO_DATA cryptoData, _In_opt_ BCRYPT_ALG_HANDLE algHandle);

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