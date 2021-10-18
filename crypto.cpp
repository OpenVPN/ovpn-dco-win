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

#include <ntddk.h>
#include <bcrypt.h>

#include "crypto.h"
#include "trace.h"
#include "pktid.h"
#include "socket.h"

OVPN_CRYPTO_DECRYPT OvpnCryptoDecryptNone;

_Use_decl_annotations_
NTSTATUS OvpnCryptoDecryptNone(OvpnCryptoKeySlot* keySlot, UCHAR* cipherTextBuffer, UCHAR* plainTextBuffer,
    SIZE_T cipherTextSize, SIZE_T plainTextBufferMaxSize, SIZE_T* plainTextBufferFinalSize)
{
    UNREFERENCED_PARAMETER(keySlot);
    UNREFERENCED_PARAMETER(plainTextBufferMaxSize);

    /* OP header size + Packet ID */
    constexpr int payloadOffset = OVPN_DATA_V2_LEN + 4;

    RtlCopyMemory(plainTextBuffer, cipherTextBuffer +
        payloadOffset, cipherTextSize - payloadOffset);

    *plainTextBufferFinalSize = cipherTextSize - payloadOffset;

    return STATUS_SUCCESS;
}

OVPN_CRYPTO_ENCRYPT OvpnCryptoEncryptNone;

UINT
OvpnCryptoOpCompose(UINT opcode, UINT keyId)
{
    return (opcode << OVPN_OPCODE_SHIFT) | keyId;
}

static
UINT
OvpnProtoOp32Compose(UINT opcode, UINT keyId, UINT opPeerId)
{
    UINT op8 = OvpnCryptoOpCompose(opcode, keyId);

    if (opcode == OVPN_OP_DATA_V2)
        return (op8 << 24) | (opPeerId & 0x00FFFFFF);

    return op8;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncryptNone(OvpnCryptoKeySlot* keySlot, OVPN_TX_BUFFER* buffer)
{
    UNREFERENCED_PARAMETER(keySlot);

    // prepend with pktid
    PUCHAR buf = OvpnTxBufferPush(buffer, 4);
    static ULONG pktid;
    ULONG pktidNetwork = RtlUlongByteSwap(pktid++);
    RtlCopyMemory(buf, &pktidNetwork, 4);

    // prepend with opcode, key-id and peer-id
    ULONG op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, 0, 0);
    op = RtlUlongByteSwap(op);
    buf = OvpnTxBufferPush(buffer, OVPN_DATA_V2_LEN);
    RtlCopyMemory(buf, &op, OVPN_DATA_V2_LEN);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoInitAlgHandle(BCRYPT_ALG_HANDLE* algHandle)
{
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptOpenAlgorithmProvider(algHandle, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH));
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(*algHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));

done:
    return status;
}

OVPN_CRYPTO_DECRYPT OvpnCryptoDecryptAEAD;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoDecryptAEAD(OvpnCryptoKeySlot* keySlot, UCHAR* cipherTextBuffer, UCHAR* plainTextBuffer,
    SIZE_T cipherTextSize, SIZE_T plainTextBufferMaxSize, SIZE_T* plainTextBufferFinalSize)
{
    // prepare nonce, which is 4 bytes pktid + 8 bytes nonce_tail
    UCHAR nonce[12];
    RtlCopyMemory(nonce, cipherTextBuffer + OVPN_DATA_V2_LEN, 4);
    RtlCopyMemory(nonce + 4, &keySlot->DecNonceTail, sizeof(keySlot->DecNonceTail));

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbTag = cipherTextBuffer + OVPN_DATA_V2_LEN + 4;
    authInfo.cbTag = 16;
    authInfo.pbAuthData = cipherTextBuffer;
    authInfo.cbAuthData = OVPN_DATA_V2_LEN + 4;

    constexpr int payloadOffset = OVPN_DATA_V2_LEN + 4 + 16; // op + pktid + auth_tag

    ULONG bytesDone = 0;
    NTSTATUS status;
    LOG_IF_NOT_NT_SUCCESS(status = BCryptDecrypt(keySlot->DecKey, cipherTextBuffer + payloadOffset, (ULONG)cipherTextSize - payloadOffset, &authInfo, NULL, 0,
        plainTextBuffer, (ULONG)plainTextBufferMaxSize, &bytesDone, 0));

    if (!NT_SUCCESS(status)) {
        *plainTextBufferFinalSize = 0;
    } else {
        UINT32 pktId = RtlUlongByteSwap(*(UINT32*)nonce);
        status = OvpnPktidRecvVerify(&keySlot->PktidRecv, pktId);

        if (NT_SUCCESS(status)) {
            *plainTextBufferFinalSize = bytesDone;
        }
        else {
            *plainTextBufferFinalSize = 0;
            LOG_ERROR("Invalid pktId", TraceLoggingUInt32(pktId, "pktId"));
        }
    }

    return status;
}

OVPN_CRYPTO_ENCRYPT OvpnCryptoEncryptAEAD;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncryptAEAD(OvpnCryptoKeySlot* keySlot, OVPN_TX_BUFFER* buffer)
{
    /*
    AEAD Nonce :

         [Packet ID] [HMAC keying material]
         [4 bytes  ] [8 bytes             ]
         [AEAD nonce total : 12 bytes     ]

    TLS wire protocol :

         [DATA_V2 opcode] [Packet ID] [AEAD Auth tag] [ciphertext]
         [4 bytes       ] [4 bytes  ] [16 bytes     ]
         [AEAD additional data(AD)  ]
    */

    SIZE_T plainTextLen = buffer->Len;

    // prepend with auth_tag
    PUCHAR tag = OvpnTxBufferPush(buffer, 16);

    // calculate pktid
    UINT32 pktid;
    NTSTATUS status = OvpnPktidXmitNext(&keySlot->PktidXmit, &pktid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ULONG pktidNetwork = RtlUlongByteSwap(pktid);

    // calculate nonce, which is 4 bytes pktid + 8 bytes nonce_tail
    UCHAR nonce[12];
    RtlCopyMemory(nonce, &pktidNetwork, 4);
    RtlCopyMemory(nonce + 4, keySlot->EncNonceTail, sizeof(keySlot->EncNonceTail));

    // prepend with pktid
    PUCHAR buf = OvpnTxBufferPush(buffer, 4);
    RtlCopyMemory(buf, &pktidNetwork, 4);

    // prepend with opcode, key-id and peer-id
    ULONG op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, keySlot->KeyId, keySlot->PeerId);
    op = RtlUlongByteSwap(op);
    buf = OvpnTxBufferPush(buffer, OVPN_DATA_V2_LEN);
    RtlCopyMemory(buf, &op, OVPN_DATA_V2_LEN);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;
    authInfo.pbAuthData = buffer->Data;
    authInfo.cbAuthData = OVPN_DATA_V2_LEN + 4;

    constexpr int payloadOffset = OVPN_DATA_V2_LEN + 4 + 16;

    ULONG bytesDone = 0;
    LOG_IF_NOT_NT_SUCCESS(status = BCryptEncrypt(keySlot->EncKey, buffer->Data + payloadOffset, (ULONG)plainTextLen, &authInfo, NULL, 0, buffer->Data + payloadOffset,
        OVPN_SOCKET_PACKET_BUFFER_SIZE, &bytesDone, 0));
    if (!NT_SUCCESS(status)) {
        buffer->Len = 0;
    }
    else {
        buffer->Len = payloadOffset + (SIZE_T)bytesDone; // op + pktid + auth_tag + ciphertext
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoNewKey(OvpnCryptoContext* cryptoContext, POVPN_CRYPTO_DATA cryptoData)
{
    OvpnCryptoKeySlot* keySlot = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (cryptoData->KeySlot == OVPN_KEY_SLOT::OVPN_KEY_SLOT_PRIMARY) {
        keySlot = &cryptoContext->Primary;
    }
    else if (cryptoData->KeySlot == OVPN_KEY_SLOT::OVPN_KEY_SLOT_SECONDARY) {
        keySlot = &cryptoContext->Secondary;
    }
    else {
        LOG_ERROR("Invalid key slot", TraceLoggingValue((int)cryptoData->KeySlot, "keySlot"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM) {
        // destroy previous keys
        if (keySlot->EncKey) {
            BCryptDestroyKey(keySlot->EncKey);
            keySlot->EncKey = NULL;
        }

        if (keySlot->DecKey) {
            BCryptDestroyKey(keySlot->DecKey);
            keySlot->DecKey = NULL;
        }

        // generate keys from key materials
        GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(cryptoContext->AlgHandle, &keySlot->EncKey, NULL, 0, cryptoData->Encrypt.Key, cryptoData->Encrypt.KeyLen, 0));
        GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(cryptoContext->AlgHandle, &keySlot->DecKey, NULL, 0, cryptoData->Decrypt.Key, cryptoData->Decrypt.KeyLen, 0));

        // copy nonce tails
        RtlCopyMemory(keySlot->EncNonceTail, cryptoData->Encrypt.NonceTail, sizeof(cryptoData->Encrypt.NonceTail));
        RtlCopyMemory(keySlot->DecNonceTail, cryptoData->Decrypt.NonceTail, sizeof(cryptoData->Decrypt.NonceTail));

        cryptoContext->Encrypt = OvpnCryptoEncryptAEAD;
        cryptoContext->Decrypt = OvpnCryptoDecryptAEAD;

        keySlot->KeyId = cryptoData->KeyId;
        keySlot->PeerId = cryptoData->PeerId;

        LOG_INFO("Key installed", TraceLoggingValue(cryptoData->KeyId, "KeyId"), TraceLoggingValue(cryptoData->KeyId, "PeerId"));
    }
    else if (cryptoData->CipherAlg == OVPN_CIPHER_ALG_NONE) {
        cryptoContext->Encrypt = OvpnCryptoEncryptNone;
        cryptoContext->Decrypt = OvpnCryptoDecryptNone;

        LOG_INFO("Using cipher none");
    }
    else {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown OVPN_CIPHER_ALG", TraceLoggingValue((int)cryptoData->CipherAlg, "CipherAlg"));
        goto done;
    }

    // reset pktid for a new key
    RtlZeroMemory(&keySlot->PktidXmit, sizeof(keySlot->PktidXmit));
    RtlZeroMemory(&keySlot->PktidRecv, sizeof(keySlot->PktidRecv));

done:
    return status;
}

_Use_decl_annotations_
OvpnCryptoKeySlot*
OvpnCryptoKeySlotFromKeyId(OvpnCryptoContext* cryptoContext, unsigned int keyId)
{
    if (cryptoContext->Primary.KeyId == keyId)
        return &cryptoContext->Primary;
    else if (cryptoContext->Secondary.KeyId == keyId) {
        return &cryptoContext->Secondary;
    }

    LOG_ERROR("No KeySlot for KeyId", TraceLoggingValue(keyId, "KeyId"));

    return NULL;
}

_Use_decl_annotations_
VOID
OvpnCryptoSwapKeys(OvpnCryptoContext* cryptoContext)
{
    OvpnCryptoKeySlot keySlot;

    RtlCopyMemory(&keySlot, &cryptoContext->Primary, sizeof(keySlot));
    RtlCopyMemory(&cryptoContext->Primary, &cryptoContext->Secondary, sizeof(keySlot));
    RtlCopyMemory(&cryptoContext->Secondary, &keySlot, sizeof(keySlot));

    LOG_INFO("Key swapped", TraceLoggingValue(cryptoContext->Primary.KeyId, "key1"), TraceLoggingValue(cryptoContext->Secondary.KeyId, "key2"));
}

_Use_decl_annotations_
VOID
OvpnCryptoUninit(OvpnCryptoContext* cryptoContext)
{
    if (cryptoContext->Primary.EncKey) {
        BCryptDestroyKey(cryptoContext->Primary.EncKey);
    }

    if (cryptoContext->Primary.DecKey) {
        BCryptDestroyKey(cryptoContext->Primary.DecKey);
    }

    if (cryptoContext->Secondary.EncKey) {
        BCryptDestroyKey(cryptoContext->Secondary.EncKey);
    }

    if (cryptoContext->Secondary.DecKey) {
        BCryptDestroyKey(cryptoContext->Secondary.DecKey);
    }

    RtlZeroMemory(cryptoContext, sizeof(OvpnCryptoContext));
}
