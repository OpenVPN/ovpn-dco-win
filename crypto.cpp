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

OVPN_CRYPTO_DECRYPT OvpnCryptoDecryptNone;

_Use_decl_annotations_
NTSTATUS OvpnCryptoDecryptNone(OvpnCryptoKeySlot* keySlot, UCHAR* bufIn, SIZE_T len, UCHAR* bufOut, INT32 cryptoOptions)
{
    UNREFERENCED_PARAMETER(keySlot);

    BOOLEAN pktId64bit = cryptoOptions & CRYPTO_OPTIONS_64BIT_PKTID;
    BOOLEAN cryptoOverhead = OVPN_DATA_V2_LEN + pktId64bit ? 8 : 4;

    if (len < cryptoOverhead) {
        LOG_WARN("Packet too short", TraceLoggingValue(len, "len"));
        return STATUS_DATA_ERROR;
    }

    RtlCopyMemory(bufOut, bufIn, len);

    return STATUS_SUCCESS;
}

OVPN_CRYPTO_ENCRYPT OvpnCryptoEncryptNone;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncryptNone(OvpnCryptoKeySlot* keySlot, UCHAR* buf, SIZE_T len, INT32 cryptoOptions)
{
    UNREFERENCED_PARAMETER(keySlot);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(cryptoOptions);

    // prepend with opcode, key-id and peer-id
    UINT32 op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, 0, 0);
    op = RtlUlongByteSwap(op);
    *(UINT32*)(buf) = op;

    // prepend with pktid
    static ULONG pktid;
    ULONG pktidNetwork = RtlUlongByteSwap(pktid++);
    *(UINT32*)(buf + OVPN_DATA_V2_LEN) = pktidNetwork;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoInitAlgHandles(BCRYPT_ALG_HANDLE* aesAlgHandle, BCRYPT_ALG_HANDLE* chachaAlgHandle)
{
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptOpenAlgorithmProvider(aesAlgHandle, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH));
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(*aesAlgHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));

    // available starting from Windows 11
    LOG_IF_NOT_NT_SUCCESS(BCryptOpenAlgorithmProvider(chachaAlgHandle, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH));
done:
    return status;
}

_Use_decl_annotations_
VOID
OvpnCryptoUninitAlgHandles(_In_ BCRYPT_ALG_HANDLE aesAlgHandle, BCRYPT_ALG_HANDLE chachaAlgHandle)
{
    if (aesAlgHandle) {
        LOG_IF_NOT_NT_SUCCESS(BCryptCloseAlgorithmProvider(aesAlgHandle, 0));
    }

    if (chachaAlgHandle) {
        LOG_IF_NOT_NT_SUCCESS(BCryptCloseAlgorithmProvider(chachaAlgHandle, 0));
    }
}

#define GET_SYSTEM_ADDRESS_MDL(buf, mdl) { \
    buf = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute); \
    if (buf == NULL) { \
        LOG_ERROR("MmGetSystemAddressForMdlSafe() returned NULL"); \
        return STATUS_DATA_ERROR; \
    } \
}

static
NTSTATUS
OvpnCryptoAEADDoWork(BOOLEAN encrypt, OvpnCryptoKeySlot* keySlot, UCHAR *bufIn, SIZE_T len, UCHAR* bufOut, INT32 cryptoOptions)
{
    /*
    AEAD Nonce :

     [Packet ID] [HMAC keying material]
     [4/8 bytes] [8/4 bytes           ]
     [AEAD nonce total : 12 bytes     ]

    TLS wire protocol :

    Packet ID is 8 bytes long with CRYPTO_OPTIONS_64BIT_PKTID.

     [DATA_V2 opcode] [Packet ID] [AEAD Auth tag] [ciphertext]
     [4 bytes       ] [4/8 bytes] [16 bytes     ]
     [AEAD additional data(AD)  ]

    With CRYPTO_OPTIONS_AEAD_TAG_END AEAD Auth tag is placed after ciphertext:

     [DATA_V2 opcode] [Packet ID] [ciphertext] [AEAD Auth tag]
     [4 bytes       ] [4/8 bytes]              [16 bytes     ]
     [AEAD additional data(AD)  ]
    */

    NTSTATUS status = STATUS_SUCCESS;

    BOOLEAN pktId64bit = cryptoOptions & CRYPTO_OPTIONS_64BIT_PKTID;

    SIZE_T cryptoOverhead = OVPN_DATA_V2_LEN + AEAD_AUTH_TAG_LEN + (pktId64bit ? 8 : 4);

    if (len < cryptoOverhead) {
        LOG_WARN("Packet too short", TraceLoggingValue(len, "len"));
        return STATUS_DATA_ERROR;
    }

    UCHAR nonce[12];
    if (encrypt) {
        // prepend with opcode, key-id and peer-id
        UINT32 op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, keySlot->KeyId, keySlot->PeerId);
        op = RtlUlongByteSwap(op);
        *reinterpret_cast<UINT32*>(bufOut) = op;

        if (pktId64bit)
        {
            // calculate pktid
            UINT64 pktid;
            GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPktidXmitNext(&keySlot->PktidXmit, &pktid, true));
            ULONG64 pktidNetwork = RtlUlonglongByteSwap(pktid);

            // calculate nonce, which is pktid + nonce_tail
            RtlCopyMemory(nonce, &pktidNetwork, 8);
            RtlCopyMemory(nonce + 8, keySlot->EncNonceTail, 4);

            // prepend with pktid
            *reinterpret_cast<UINT64*>(bufOut + OVPN_DATA_V2_LEN) = pktidNetwork;
        }
        else
        {
            // calculate pktid
            UINT32 pktid;
            GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPktidXmitNext(&keySlot->PktidXmit, &pktid, false));
            ULONG pktidNetwork = RtlUlongByteSwap(pktid);

            // calculate nonce, which is pktid + nonce_tail
            RtlCopyMemory(nonce, &pktidNetwork, 4);
            RtlCopyMemory(nonce + 4, keySlot->EncNonceTail, 8);

            // prepend with pktid
            *reinterpret_cast<UINT32*>(bufOut + OVPN_DATA_V2_LEN) = pktidNetwork;
        }
    }
    else {
        ULONG64 pktId;

        RtlCopyMemory(nonce, bufIn + OVPN_DATA_V2_LEN, pktId64bit ? 8 : 4);
        RtlCopyMemory(nonce + (pktId64bit ? 8 : 4), &keySlot->DecNonceTail, pktId64bit ? 4 : 8);
        if (pktId64bit)
        {
            pktId = RtlUlonglongByteSwap(*reinterpret_cast<UINT64*>(nonce));
        }
        else
        {
            pktId = static_cast<ULONG64>(RtlUlongByteSwap(*reinterpret_cast<UINT32*>(nonce)));
        }

        status = OvpnPktidRecvVerify(&keySlot->PktidRecv, pktId);

        if (!NT_SUCCESS(status)) {
            LOG_ERROR("Invalid pktId", TraceLoggingUInt64(pktId, "pktId"));
            return STATUS_DATA_ERROR;
        }
    }

    // we prepended buf with crypto overhead
    len -= cryptoOverhead;

    BOOLEAN aeadTagEnd = cryptoOptions & CRYPTO_OPTIONS_AEAD_TAG_END;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbTag = (encrypt ? bufOut : bufIn) + OVPN_DATA_V2_LEN + (pktId64bit ? 8 : 4) + (aeadTagEnd ? len : 0);
    authInfo.cbTag = AEAD_AUTH_TAG_LEN;
    authInfo.pbAuthData = (encrypt ? bufOut : bufIn);
    authInfo.cbAuthData = OVPN_DATA_V2_LEN + (pktId64bit ? 8 : 4);

    auto payloadOffset = OVPN_DATA_V2_LEN + (pktId64bit ? 8 : 4) + (aeadTagEnd ? 0 : AEAD_AUTH_TAG_LEN);
    bufOut += payloadOffset;
    bufIn += payloadOffset;

    // non-chaining mode
    ULONG bytesDone = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, encrypt ?
        BCryptEncrypt(keySlot->EncKey, bufIn, (ULONG)len, &authInfo, NULL, 0, bufOut, (ULONG)len, &bytesDone, 0) :
        BCryptDecrypt(keySlot->DecKey, bufIn, (ULONG)len, &authInfo, NULL, 0, bufOut, (ULONG)len, &bytesDone, 0)
    );

done:
    return status;
}

OVPN_CRYPTO_DECRYPT OvpnCryptoDecryptAEAD;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoDecryptAEAD(OvpnCryptoKeySlot* keySlot, UCHAR* bufIn, SIZE_T len, UCHAR* bufOut, INT32 cryptoOptions)
{
    return OvpnCryptoAEADDoWork(FALSE, keySlot, bufIn, len, bufOut, cryptoOptions);
}

OVPN_CRYPTO_ENCRYPT OvpnCryptoEncryptAEAD;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncryptAEAD(OvpnCryptoKeySlot* keySlot, UCHAR* buf, SIZE_T len, INT32 cryptoOptions)
{
    return OvpnCryptoAEADDoWork(TRUE, keySlot, buf, len, buf, cryptoOptions);
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoNewKey(OvpnCryptoContext* cryptoContext, POVPN_CRYPTO_DATA_V2 cryptoDataV2)
{
    OvpnCryptoKeySlot* keySlot = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    POVPN_CRYPTO_DATA cryptoData = &cryptoDataV2->V1;

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

    if (cryptoDataV2->CryptoOptions & CRYPTO_OPTIONS_64BIT_PKTID)
    {
        cryptoContext->CryptoOptions |= CRYPTO_OPTIONS_64BIT_PKTID;
    }
    if (cryptoDataV2->CryptoOptions & CRYPTO_OPTIONS_AEAD_TAG_END)
    {
        cryptoContext->CryptoOptions |= CRYPTO_OPTIONS_AEAD_TAG_END;
    }

    if ((cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM) || (cryptoData->CipherAlg == OVPN_CIPHER_ALG_CHACHA20_POLY1305)) {
        // destroy previous keys
        if (keySlot->EncKey) {
            BCryptDestroyKey(keySlot->EncKey);
            keySlot->EncKey = NULL;
        }

        if (keySlot->DecKey) {
            BCryptDestroyKey(keySlot->DecKey);
            keySlot->DecKey = NULL;
        }

        BCRYPT_ALG_HANDLE algHandle = NULL;
        if (cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM) {
            algHandle = cryptoContext->AesAlgHandle;
        }
        else {
            if (cryptoContext->ChachaAlgHandle == NULL) {
                LOG_ERROR("CHACHA20-POLY1305 is not available");
                status = STATUS_INVALID_DEVICE_REQUEST;
                goto done;
            }
            algHandle = cryptoContext->ChachaAlgHandle;
        }

        if ((cryptoData->Encrypt.KeyLen > 32) || (cryptoData->Decrypt.KeyLen > 32))
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            LOG_ERROR("Incorrect encrypt or decrypt key length", TraceLoggingValue(cryptoData->Encrypt.KeyLen, "Encrypt.KeyLen"),
                TraceLoggingValue(cryptoData->Decrypt.KeyLen, "Decrypt.KeyLen"));
            goto done;
        }

        // generate keys from key materials
        GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(algHandle, &keySlot->EncKey, NULL, 0, cryptoData->Encrypt.Key, cryptoData->Encrypt.KeyLen, 0));
        GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(algHandle, &keySlot->DecKey, NULL, 0, cryptoData->Decrypt.Key, cryptoData->Decrypt.KeyLen, 0));

        // copy nonce tails
        RtlCopyMemory(keySlot->EncNonceTail, cryptoData->Encrypt.NonceTail, sizeof(cryptoData->Encrypt.NonceTail));
        RtlCopyMemory(keySlot->DecNonceTail, cryptoData->Decrypt.NonceTail, sizeof(cryptoData->Decrypt.NonceTail));

        cryptoContext->Encrypt = OvpnCryptoEncryptAEAD;
        cryptoContext->Decrypt = OvpnCryptoDecryptAEAD;

        keySlot->KeyId = cryptoData->KeyId;
        keySlot->PeerId = cryptoData->PeerId;

        LOG_INFO("New key", TraceLoggingValue(cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM ? "aes-gcm" : "chacha20-poly1305", "alg"),
            TraceLoggingValue(cryptoData->KeyId, "KeyId"), TraceLoggingValue(cryptoData->KeyId, "PeerId"));
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
