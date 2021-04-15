/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
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

#include "driverhelper\buffers.h"
#include "pktid.h"
#include "uapi\ovpn-dco.h"

struct OvpnCryptoKeySlot
{
    BCRYPT_KEY_HANDLE EncKey;
    BCRYPT_KEY_HANDLE DecKey;

    UCHAR EncNonceTail[8];
    UCHAR DecNonceTail[8];

    unsigned int KeyId;
    int PeerId;

    OvpnPktidXmit PktidXmit;
    OvpnPktidRecv PktidRecv;
};

_Function_class_(OVPN_CRYPTO_ENCRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_ENCRYPT(_In_ OvpnCryptoKeySlot* keySlot, _Inout_ OVPN_TX_BUFFER* buffer);
typedef OVPN_CRYPTO_ENCRYPT* POVPN_CRYPTO_ENCRYPT;

_Function_class_(OVPN_CRYPTO_DECRYPT)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
typedef
NTSTATUS
OVPN_CRYPTO_DECRYPT(_In_ OvpnCryptoKeySlot* keySlot, _In_reads_(cipherTextSize) UCHAR* cipherTextBuffer,
    _Out_writes_(plainTextBufferMaxSize) UCHAR* plainTextBuffer, SIZE_T cipherTextSize, SIZE_T plainTextBufferMaxSize, _Out_ SIZE_T* plainTextBufferFinalSize);
typedef OVPN_CRYPTO_DECRYPT* POVPN_CRYPTO_DECRYPT;

struct OvpnCryptoContext
{
    BCRYPT_ALG_HANDLE AlgHandle;

    // TODO: locks

    OvpnCryptoKeySlot Primary;
    OvpnCryptoKeySlot Secondary;

    POVPN_CRYPTO_ENCRYPT Encrypt;
    POVPN_CRYPTO_DECRYPT Decrypt;
};

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnCryptoInitAlgHandle(_Outptr_ BCRYPT_ALG_HANDLE* algHandle);

VOID
OvpnCryptoUninit(_In_ OvpnCryptoContext* cryptoContext);

_Must_inspect_result_
NTSTATUS
OvpnCryptoNewKey(_In_ OvpnCryptoContext* cryptoContext, _In_ POVPN_CRYPTO_DATA cryptoData);

_Must_inspect_result_
OvpnCryptoKeySlot*
OvpnCryptoKeySlotFromKeyId(_In_ OvpnCryptoContext* cryptoContext, unsigned int keyId);

VOID
OvpnCryptoSwapKeys(_In_ OvpnCryptoContext* cryptoContext);
