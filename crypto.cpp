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
#include <ntstrsafe.h>

#include "crypto.h"
#include "trace.h"
#include "pktid.h"
#include "socket.h"
#include "peer.h"

UINT
OvpnCryptoOpCompose(UINT opcode, UINT keyId)
{
    return (opcode << OVPN_OPCODE_SHIFT) | keyId;
}

static
VOID
OvpnCryptoUpgradeLock(_In_ OvpnPeerContext* peer, _In_ BOOLEAN atDpcLevel, _Inout_opt_ PKIRQL kirql)
{
    if (atDpcLevel) {
        ExReleaseSpinLockSharedFromDpcLevel(&peer->SpinLock);
        ExAcquireSpinLockExclusiveAtDpcLevel(&peer->SpinLock);
    }
    else {
        NT_ASSERT(kirql != nullptr);

        KIRQL previousIrql = *kirql;

        ExReleaseSpinLockShared(&peer->SpinLock, previousIrql);

        KIRQL acquiredIrql = ExAcquireSpinLockExclusive(&peer->SpinLock);
        NT_ASSERT(acquiredIrql == previousIrql);
        *kirql = acquiredIrql;
    }
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoCallWithRetry(
    OvpnPeerContext* peer,
    BOOLEAN atDpcLevel,
    PBOOLEAN exclusive,
    PKIRQL kirql,
    POVPN_CRYPTO_RETRY_ROUTINE routine,
    PVOID context)
{
    NT_ASSERT(peer != nullptr);
    NT_ASSERT(routine != nullptr);

    BOOLEAN allowRekey = (exclusive != nullptr) && *exclusive;

    for (;;) {
        OvpnCryptoContext* cryptoContext = &peer->CryptoContext;
        NTSTATUS status = routine(cryptoContext, allowRekey, context);

        if (status != STATUS_OVPN_CRYPTO_RETRY) {
            return status;
        }

        if (!allowRekey) {
            // Drop the shared lock before upgrading. The caller owns a peer
            // reference, so the context remains valid while we temporarily
            // release the lock and the loop below re-reads the crypto state
            // under exclusive ownership.
            OvpnCryptoUpgradeLock(peer, atDpcLevel, kirql);
            allowRekey = TRUE;

            if (exclusive != nullptr) {
                *exclusive = TRUE;
            }

            continue;
        }

        LOG_ERROR("Crypto helper requested retry under exclusive lock");
        return STATUS_UNSUCCESSFUL;
    }
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoInvokeEncrypt(
    OvpnCryptoContext* cryptoContext,
    BOOLEAN allowRekey,
    PVOID context)
{
    auto params = reinterpret_cast<OvpnCryptoEncryptParams*>(context);

    if ((cryptoContext == nullptr) || (cryptoContext->Encrypt == nullptr)) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    NT_ASSERT(params != nullptr);

    return cryptoContext->Encrypt(&cryptoContext->Primary, params->Buffer, params->Length, &cryptoContext->Options, allowRekey);
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoInvokeDecrypt(
    OvpnCryptoContext* cryptoContext,
    BOOLEAN allowRekey,
    PVOID context)
{
    auto params = reinterpret_cast<OvpnCryptoDecryptParams*>(context);

    if ((cryptoContext == nullptr) || (cryptoContext->Decrypt == nullptr)) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    NT_ASSERT(params != nullptr);

    OvpnCryptoKeySlot* keySlot = OvpnCryptoKeySlotFromKeyId(cryptoContext, params->KeyId);
    if (keySlot == nullptr) {
        LOG_ERROR("keyId <keyId> not found", TraceLoggingValue(params->KeyId, "keyId"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS status = cryptoContext->Decrypt(
        keySlot,
        params->CipherText,
        params->Length,
        params->PlainText,
        &cryptoContext->Options,
        allowRekey);

    return status;
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
NTSTATUS OvpnCryptoDecryptNone(OvpnCryptoKeySlot* keySlot, UCHAR* bufIn, SIZE_T len, UCHAR* bufOut, OvpnCryptoOptions* opts, BOOLEAN allowRekey)
{
    UNREFERENCED_PARAMETER(keySlot);
    UNREFERENCED_PARAMETER(allowRekey);

    BOOLEAN useEpoch = (opts != NULL) && opts->UseEpoch;
    SIZE_T pktIdLen = useEpoch ? 8 : 4;
    SIZE_T authTagFront = useEpoch ? 0 : AEAD_AUTH_TAG_LEN;
    SIZE_T cryptoOverhead = OVPN_DATA_V2_LEN + pktIdLen + authTagFront;

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
OvpnCryptoEncryptNone(OvpnCryptoKeySlot* keySlot, UCHAR* buf, SIZE_T len, OvpnCryptoOptions* opts, BOOLEAN allowRekey)
{
    UNREFERENCED_PARAMETER(keySlot);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(opts);
    UNREFERENCED_PARAMETER(allowRekey);

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
OvpnCryptoInitAlgHandles(BCRYPT_ALG_HANDLE* aesAlgHandle, BCRYPT_ALG_HANDLE* chachaAlgHandle, BCRYPT_ALG_HANDLE* hkdfAlgHandle)
{
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptOpenAlgorithmProvider(aesAlgHandle, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH));
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(*aesAlgHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));

    // used by epoch data channel
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptOpenAlgorithmProvider(hkdfAlgHandle, BCRYPT_HKDF_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH));

    // available starting from Windows 11
    LOG_IF_NOT_NT_SUCCESS(BCryptOpenAlgorithmProvider(chachaAlgHandle, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH));
done:
    return status;
}

_Use_decl_annotations_
VOID
OvpnCryptoUninitAlgHandles(_In_ BCRYPT_ALG_HANDLE aesAlgHandle, BCRYPT_ALG_HANDLE chachaAlgHandle, BCRYPT_ALG_HANDLE hkdfAlgHandle)
{
    if (aesAlgHandle) {
        LOG_IF_NOT_NT_SUCCESS(BCryptCloseAlgorithmProvider(aesAlgHandle, 0));
    }

    if (chachaAlgHandle) {
        LOG_IF_NOT_NT_SUCCESS(BCryptCloseAlgorithmProvider(chachaAlgHandle, 0));
    }

    if (hkdfAlgHandle) {
        LOG_IF_NOT_NT_SUCCESS(BCryptCloseAlgorithmProvider(hkdfAlgHandle, 0));
    }
}

#define GET_SYSTEM_ADDRESS_MDL(buf, mdl) { \
    buf = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute); \
    if (buf == NULL) { \
        LOG_ERROR("MmGetSystemAddressForMdlSafe() returned NULL"); \
        return STATUS_DATA_ERROR; \
    } \
}

NTSTATUS
OvpnCryptoCheckReplay(OvpnCryptoKeySlot* keySlot, ULONG64 packet_id_net, UINT16 epoch, OvpnCryptoOptions *opts, BOOLEAN allowRekey)
{
    OvpnPktidRecv* recv = NULL;

    if (epoch == 0 || keySlot->Decrypt.Epoch == epoch) {
        recv = &keySlot->PktidRecv;
    }
    else if (epoch == keySlot->RetiringEpochDataReceiveKey.Epoch) {
        recv = &keySlot->PktidRecvRetiring;
    }
    else {
        if (!allowRekey) {
            return STATUS_OVPN_CRYPTO_RETRY;
        }

        /* We have an epoch that is neither current or old recv key but
         * is authenticated, ie we need to move to a new current recv key */
        LOG_INFO("Received data packet with new epoch. Updating receive key", TraceLoggingValue(epoch, "epoch"));
        OvpnCryptoEpochReplaceUpdateRecvKey(keySlot, epoch, opts);
        recv = &keySlot->PktidRecv;
    }

    return OvpnPktidRecvVerify(recv, packet_id_net);
}

/*
AEAD Nonce :

    [Packet ID] [HMAC keying material]
    [4 bytes  ] [4 bytes             ]
    [AEAD nonce total : 12 bytes     ]

TLS wire protocol :

    [DATA_V2 opcode] [Packet ID] [AEAD Auth tag] [ciphertext]
    [4 bytes       ] [4 bytes  ] [16 bytes     ]
    [AEAD additional data(AD)  ]

New data format, with epoch keys and 64bit packet id:

    struct aead_packet {
    int opcode:5;
    int key_id:3;
    int peer_id:24;
    uint64_t packet_id;
    uint8_t* encrypted_payload;
    uint8_t[16] authentication_tag;
    }

    struct packet_id {
    uint epoch:16;
    uint epoch_counter:48;
    }

    authenticated_data = opcode| key_id | peer_id | packet_id
*/


OVPN_CRYPTO_DECRYPT OvpnCryptoDecryptAEAD;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoDecryptAEAD(OvpnCryptoKeySlot* keySlot, UCHAR* bufIn, SIZE_T len, UCHAR* bufOut, OvpnCryptoOptions* opts, BOOLEAN allowRekey)
{
    NTSTATUS status = STATUS_SUCCESS;

    BOOLEAN authTagEnd = opts->UseEpoch;
    ULONG pktidLen = opts->UseEpoch ? 8 : 4;
    ULONG cryptoOverhead = OVPN_DATA_V2_LEN + AEAD_AUTH_TAG_LEN + pktidLen;

    if (len < cryptoOverhead) {
        LOG_WARN("Packet too short", TraceLoggingValue(len, "len"));
        return STATUS_DATA_ERROR;
    }

    // we prepended buf with crypto overhead
    len -= cryptoOverhead;

    OvpnCryptoKeyContext* decryptKey = &keySlot->Decrypt;
    UINT64 packet_id = 0;
    UINT16 rx_epoch = 0;

    UCHAR nonce[12];

    if (opts->UseEpoch) {
        // read packet_id
        UINT64 packet_id_net;
        RtlCopyMemory(&packet_id_net, bufIn + OVPN_DATA_V2_LEN, sizeof(packet_id_net));
        packet_id = RtlUlonglongByteSwap(packet_id_net);

        // get epoch number and counter
        rx_epoch = (UINT16)(packet_id >> 48);
        if (rx_epoch == 0) {
            LOG_ERROR("Invalid epoch 0");
            return STATUS_DATA_ERROR;
        }

        decryptKey = OvpnCryptoEpochLookupDecryptKey(keySlot, rx_epoch);
        if (decryptKey == NULL) {
            LOG_ERROR("Data packet with unknown epoch", TraceLoggingValue(rx_epoch, "epoch"));
            return STATUS_DATA_ERROR;
        }

        OvpnCryptoMakeEpochNonce(decryptKey->ImplicitIV, packet_id_net, nonce);
    }
    else {
        RtlCopyMemory(nonce, bufIn + OVPN_DATA_V2_LEN, 4);
        RtlCopyMemory(nonce + 4, decryptKey->ImplicitIV + 4, 8);

        packet_id = static_cast<ULONG64>(RtlUlongByteSwap(*reinterpret_cast<UINT32*>(nonce)));
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbTag = bufIn + OVPN_DATA_V2_LEN + pktidLen + (authTagEnd ? len : 0);
    authInfo.cbTag = AEAD_AUTH_TAG_LEN;
    authInfo.pbAuthData = bufIn;
    authInfo.cbAuthData = OVPN_DATA_V2_LEN + pktidLen;

    auto payloadOffset = OVPN_DATA_V2_LEN + pktidLen + (authTagEnd ? 0 : AEAD_AUTH_TAG_LEN);
    bufOut += payloadOffset;
    bufIn += payloadOffset;

    // non-chaining mode
    ULONG bytesDone = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptDecrypt(decryptKey->Key, bufIn, (ULONG)len, &authInfo, NULL, 0, bufOut, (ULONG)len, &bytesDone, 0));

    status = OvpnCryptoCheckReplay(keySlot, packet_id, rx_epoch, opts, allowRekey);
    if (status == STATUS_OVPN_CRYPTO_RETRY) {
        return status;
    }

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Invalid packet_id", TraceLoggingUInt64(packet_id, "packet_id"));
        return STATUS_DATA_ERROR;
    }

done:
    return status;
}

OVPN_CRYPTO_ENCRYPT OvpnCryptoEncryptAEAD;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncryptAEAD(OvpnCryptoKeySlot* keySlot, UCHAR* buf, SIZE_T len, OvpnCryptoOptions* opts, BOOLEAN allowRekey)
{
    NTSTATUS status = STATUS_SUCCESS;

    BOOLEAN authTagEnd = opts->UseEpoch;
    ULONG pktidLen = opts->UseEpoch ? 8 : 4;
    ULONG cryptoOverhead = OVPN_DATA_V2_LEN + AEAD_AUTH_TAG_LEN + pktidLen;

    if (len < cryptoOverhead) {
        LOG_WARN("Packet too short", TraceLoggingValue(len, "len"));
        return STATUS_DATA_ERROR;
    }

    // we prepended buf with crypto overhead
    len -= cryptoOverhead;

    UINT64 packet_id = 0;

    UCHAR nonce[12];

    // prepend with opcode, key-id and peer-id
    UINT32 op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, keySlot->KeyId, keySlot->PeerId);
    op = RtlUlongByteSwap(op);
    RtlCopyMemory(buf, &op, sizeof(op));

    if (opts->UseEpoch) {
        if (keySlot->EpochKeySend.Epoch == UINT16_MAX) {
            return STATUS_BUFFER_OVERFLOW;
        }

        if (OvpnCryptoAeadUsageLimitReached(opts->AeadUsageLimit, keySlot->Encrypt.PlaintextBlocks, keySlot->PktidXmit.SeqNum) || (keySlot->PktidXmit.SeqNum == PACKET_ID_EPOCH_MAX)) {
            if (!allowRekey) {
                return STATUS_OVPN_CRYPTO_RETRY;
            }

            OvpnCryptoEpochIterateSendKey(keySlot, opts);
        }

        // calculate 64-bit packet-id = (epoch << 48) | ctr48
        // the overflow of pktid is checked above
        UINT64 ctr48 = InterlockedIncrementNoFence64(&keySlot->PktidXmit.SeqNum) & PACKET_ID_EPOCH_MAX;
        packet_id = ((UINT64)keySlot->Encrypt.Epoch << 48) | ctr48;

        // prepend with pktid
        UINT64 packet_id_net = RtlUlonglongByteSwap(packet_id);
        RtlCopyMemory(buf + OVPN_DATA_V2_LEN, &packet_id_net, sizeof(packet_id_net));

        OvpnCryptoMakeEpochNonce(keySlot->Encrypt.ImplicitIV, packet_id_net, nonce);
    }
    else {
        // calculate pktid
        UINT32 packet_id_32;
        GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPktidXmitNext(&keySlot->PktidXmit, &packet_id_32));
        ULONG packet_id_net = RtlUlongByteSwap(packet_id_32);

        // calculate nonce, which is pktid + nonce_tail
        RtlCopyMemory(nonce, &packet_id_net, 4);
        RtlCopyMemory(nonce + 4, keySlot->Encrypt.ImplicitIV + 4, 8);

        // prepend with pktid
        RtlCopyMemory(buf + OVPN_DATA_V2_LEN, &packet_id_net, sizeof(packet_id_net));
    }

    // update number of plaintext blocks encrypted. Use the (x + (n-1))/n trick to round up the result to the number of blocks used
    const ULONGLONG blocksize = AEAD_LIMIT_BLOCKSIZE;
    ULONGLONG inc = ((ULONGLONG)len + (blocksize - 1)) / blocksize;
    InterlockedAdd64((volatile LONG64*)&keySlot->Encrypt.PlaintextBlocks, (LONG64)inc);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbTag = buf + OVPN_DATA_V2_LEN + pktidLen + (authTagEnd ? len : 0);
    authInfo.cbTag = AEAD_AUTH_TAG_LEN;
    authInfo.pbAuthData = buf;
    authInfo.cbAuthData = OVPN_DATA_V2_LEN + pktidLen;

    auto payloadOffset = OVPN_DATA_V2_LEN + pktidLen + (authTagEnd ? 0 : AEAD_AUTH_TAG_LEN);
    buf += payloadOffset;

    // non-chaining mode
    ULONG bytesDone = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptEncrypt(keySlot->Encrypt.Key, buf, (ULONG)len, &authInfo, NULL, 0, buf, (ULONG)len, &bytesDone, 0));

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoNewKey(OvpnCryptoContext* cryptoContext, POVPN_CRYPTO_DATA_V2 cryptoDataV2, BCRYPT_ALG_HANDLE algHandle, BCRYPT_ALG_HANDLE hkdfAlgHandle)
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

    if ((cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM) || (cryptoData->CipherAlg == OVPN_CIPHER_ALG_CHACHA20_POLY1305)) {
        // destroy previous keys
        if (keySlot->Encrypt.Key) {
            BCryptDestroyKey(keySlot->Encrypt.Key);
            keySlot->Encrypt.Key = NULL;
        }

        if (keySlot->Decrypt.Key) {
            BCryptDestroyKey(keySlot->Decrypt.Key);
            keySlot->Decrypt.Key = NULL;
        }

        if ((cryptoData->Encrypt.KeyLen > 32) || (cryptoData->Decrypt.KeyLen > 32))
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            LOG_ERROR("Incorrect encrypt or decrypt key length", TraceLoggingValue(cryptoData->Encrypt.KeyLen, "Encrypt.KeyLen"),
                TraceLoggingValue(cryptoData->Decrypt.KeyLen, "Decrypt.KeyLen"));
            goto done;
        }

        cryptoContext->Options.KeyLen = cryptoData->Encrypt.KeyLen;

        if (cryptoDataV2->CryptoOptions & CRYPTO_OPTIONS_EPOCH) {
            cryptoContext->Options.AeadUsageLimit = OvpnCryptoAeadUsageLimit(cryptoData->CipherAlg);
            cryptoContext->Options.UseEpoch = TRUE;
            cryptoContext->Options.HkdfAlgHandle = hkdfAlgHandle;
            cryptoContext->Options.AeadAlgHangle = algHandle;

            keySlot->EpochKeySend.Epoch = 1;
            RtlCopyMemory(keySlot->EpochKeySend.EpochKey, cryptoData->Encrypt.Key, 32);

            keySlot->EpochKeyRecv.Epoch = 1;
            RtlCopyMemory(keySlot->EpochKeyRecv.EpochKey, cryptoData->Decrypt.Key, 32);

            OvpnCryptoEpochInitKey(&keySlot->Encrypt, &keySlot->EpochKeySend, &cryptoContext->Options);
            OvpnCryptoEpochInitKey(&keySlot->Decrypt, &keySlot->EpochKeyRecv, &cryptoContext->Options);

            RtlZeroMemory(keySlot->FutureEpochKeys, sizeof(keySlot->FutureEpochKeys));
            OvpnCryptoEpochGenerateFutureRecvKeys(keySlot, &cryptoContext->Options);
        }
        else {
            // generate keys from key materials
            GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(algHandle, &keySlot->Encrypt.Key, NULL, 0, cryptoData->Encrypt.Key, cryptoData->Encrypt.KeyLen, 0));
            GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(algHandle, &keySlot->Decrypt.Key, NULL, 0, cryptoData->Decrypt.Key, cryptoData->Decrypt.KeyLen, 0));

            // copy nonce tails
            RtlCopyMemory(keySlot->Encrypt.ImplicitIV + 4, cryptoData->Encrypt.NonceTail, sizeof(cryptoData->Encrypt.NonceTail));
            RtlCopyMemory(keySlot->Decrypt.ImplicitIV + 4, cryptoData->Decrypt.NonceTail, sizeof(cryptoData->Decrypt.NonceTail));
        }

        keySlot->KeyId = cryptoData->KeyId;
        keySlot->PeerId = cryptoData->PeerId;

        cryptoContext->Encrypt = OvpnCryptoEncryptAEAD;
        cryptoContext->Decrypt = OvpnCryptoDecryptAEAD;

        LOG_INFO("New key", TraceLoggingValue(cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM ? "aes-gcm" : "chacha20-poly1305", "alg"),
            TraceLoggingValue(cryptoData->KeyId, "KeyId"), TraceLoggingValue(cryptoData->PeerId, "PeerId"));
    }
    else if (cryptoData->CipherAlg == OVPN_CIPHER_ALG_NONE) {
        OvpnCryptoEpochUninitSlot(keySlot);

        keySlot->KeyId = cryptoData->KeyId;
        keySlot->PeerId = cryptoData->PeerId;

        RtlZeroMemory(&cryptoContext->Options, sizeof(cryptoContext->Options));

        cryptoContext->Encrypt = OvpnCryptoEncryptNone;
        cryptoContext->Decrypt = OvpnCryptoDecryptNone;

        LOG_INFO("Using cipher none");
    }
    else {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown OVPN_CIPHER_ALG", TraceLoggingValue((int)cryptoData->CipherAlg, "CipherAlg"));
        goto done;
    }

    OvpnCryptoDescribePacketLayout(cryptoContext, &cryptoContext->Layout);
    // reset pktid for a new key
    RtlZeroMemory(&keySlot->PktidXmit, sizeof(keySlot->PktidXmit));
    RtlZeroMemory(&keySlot->PktidRecv, sizeof(keySlot->PktidRecv));

done:
    return status;
}

_Use_decl_annotations_
VOID
OvpnCryptoDescribePacketLayout(const OvpnCryptoContext* cryptoContext, OvpnCryptoPacketLayout* layout)
{
    NT_ASSERT(layout != NULL);

    layout->FrontLen = OVPN_DATA_V2_LEN + 4;
    layout->TailLen = 0;

    if ((cryptoContext == NULL) || (cryptoContext->Encrypt == NULL)) {
        return;
    }

    if (cryptoContext->Encrypt == OvpnCryptoEncryptAEAD) {
        BOOLEAN useEpoch = cryptoContext->Options.UseEpoch;

        layout->FrontLen = OVPN_DATA_V2_LEN + (useEpoch ? 8 : 4);
        if (!useEpoch) {
            layout->FrontLen += AEAD_AUTH_TAG_LEN;
        }

        layout->TailLen = useEpoch ? AEAD_AUTH_TAG_LEN : 0;
    }
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
    OvpnCryptoEpochUninitSlot(&cryptoContext->Primary);
    OvpnCryptoEpochUninitSlot(&cryptoContext->Secondary);

    RtlZeroMemory(cryptoContext, sizeof(OvpnCryptoContext));
}
