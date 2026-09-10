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

#if DBG
ULONG g_OvpnTestAeadUsageLimit = 0;
#endif

UINT
OvpnCryptoOpCompose(UINT opcode, UINT keyId)
{
    return (opcode << OVPN_OPCODE_SHIFT) | keyId;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncrypt(OvpnCryptoTxContext* tx, PUCHAR buf, SIZE_T len)
{
    if (tx->Encrypt == nullptr) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    return tx->Encrypt(&tx->Primary, buf, len, &tx->Options);
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoDecrypt(OvpnCryptoRxContext* rx, UCHAR keyId, PUCHAR cipherText, SIZE_T len, PUCHAR plainText, UINT16* sendEpoch)
{
    *sendEpoch = 0;

    if (rx->Decrypt == nullptr) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    OvpnCryptoRxState* state = NULL;
    if (rx->Primary.KeyId == keyId) {
        state = &rx->Primary;
    }
    else if (rx->Secondary.KeyId == keyId) {
        state = &rx->Secondary;
    }
    else {
        LOG_ERROR("No key for KeyId", TraceLoggingValue(keyId, "KeyId"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    return rx->Decrypt(state, cipherText, len, plainText, &rx->Options, sendEpoch);
}

_Use_decl_annotations_
VOID
OvpnCryptoFollowPeerEpoch(OvpnCryptoTxContext* tx, UCHAR keyId, UINT16 epoch)
{
    // a key replaced since the receive path saw the epoch has another id and is left alone
    OvpnCryptoTxState* state = NULL;
    if (tx->Primary.KeyId == keyId) {
        state = &tx->Primary;
    }
    else if (tx->Secondary.KeyId == keyId) {
        state = &tx->Secondary;
    }

    if ((state != NULL) && tx->Options.UseEpoch) {
        OvpnCryptoEpochBumpSendKey(state, epoch, &tx->Options);
    }
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
NTSTATUS OvpnCryptoDecryptNone(OvpnCryptoRxState* rx, UCHAR* bufIn, SIZE_T len, UCHAR* bufOut, OvpnCryptoOptions* opts, UINT16* sendEpoch)
{
    UNREFERENCED_PARAMETER(rx);

    *sendEpoch = 0;

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
OvpnCryptoEncryptNone(OvpnCryptoTxState* tx, UCHAR* buf, SIZE_T len, OvpnCryptoOptions* opts)
{
    UNREFERENCED_PARAMETER(tx);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(opts);

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
OvpnCryptoCheckReplay(OvpnCryptoRxState* rx, ULONG64 packet_id_net, UINT16 epoch, OvpnCryptoOptions *opts, UINT16* sendEpoch)
{
    OvpnPktidRecv* recv = NULL;

    *sendEpoch = 0;

    if (epoch == 0 || rx->Key.Epoch == epoch) {
        recv = &rx->Pktid;
    }
    else if (epoch == rx->RetiringKey.Epoch) {
        recv = &rx->PktidRetiring;
    }
    else {
        /* We have an epoch that is neither current or old recv key but
         * is authenticated, ie we need to move to a new current recv key.
         * The send key follows in OvpnCryptoDecrypt, under TxLock. */
        LOG_INFO("Received data packet with new epoch. Updating receive key", TraceLoggingValue(epoch, "epoch"));
        OvpnCryptoEpochReplaceUpdateRecvKey(rx, epoch, opts);
        recv = &rx->Pktid;
        *sendEpoch = epoch;
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
OvpnCryptoDecryptAEAD(OvpnCryptoRxState* rx, UCHAR* bufIn, SIZE_T len, UCHAR* bufOut, OvpnCryptoOptions* opts, UINT16* sendEpoch)
{
    NTSTATUS status = STATUS_SUCCESS;

    *sendEpoch = 0;

    BOOLEAN authTagEnd = opts->UseEpoch;
    ULONG pktidLen = opts->UseEpoch ? 8 : 4;
    ULONG cryptoOverhead = OVPN_DATA_V2_LEN + AEAD_AUTH_TAG_LEN + pktidLen;

    if (len < cryptoOverhead) {
        LOG_WARN("Packet too short", TraceLoggingValue(len, "len"));
        return STATUS_DATA_ERROR;
    }

    // we prepended buf with crypto overhead
    len -= cryptoOverhead;

    OvpnCryptoKeyContext* decryptKey = &rx->Key;
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

        decryptKey = OvpnCryptoEpochLookupDecryptKey(rx, rx_epoch);
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

    status = OvpnCryptoCheckReplay(rx, packet_id, rx_epoch, opts, sendEpoch);
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
OvpnCryptoEncryptAEAD(OvpnCryptoTxState* tx, UCHAR* buf, SIZE_T len, OvpnCryptoOptions* opts)
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
    UINT32 op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, tx->KeyId, tx->PeerId);
    op = RtlUlongByteSwap(op);
    RtlCopyMemory(buf, &op, sizeof(op));

    if (opts->UseEpoch) {
        if (tx->EpochKey.Epoch == UINT16_MAX) {
            return STATUS_BUFFER_OVERFLOW;
        }

        if (OvpnCryptoAeadUsageLimitReached(opts->AeadUsageLimit, tx->Key.PlaintextBlocks, tx->Pktid.SeqNum) || (tx->Pktid.SeqNum >= PACKET_ID_EPOCH_MAX)) {
            OvpnCryptoEpochIterateSendKey(tx, opts);
        }

        // calculate 64-bit packet-id = (epoch << 48) | ctr48
        // the overflow of pktid is checked above
        UINT64 ctr48 = (UINT64)++tx->Pktid.SeqNum;
        packet_id = ((UINT64)tx->Key.Epoch << 48) | ctr48;

        // prepend with pktid
        UINT64 packet_id_net = RtlUlonglongByteSwap(packet_id);
        RtlCopyMemory(buf + OVPN_DATA_V2_LEN, &packet_id_net, sizeof(packet_id_net));

        OvpnCryptoMakeEpochNonce(tx->Key.ImplicitIV, packet_id_net, nonce);
    }
    else {
        // calculate pktid
        UINT32 packet_id_32;
        GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPktidXmitNext(&tx->Pktid, &packet_id_32));
        ULONG packet_id_net = RtlUlongByteSwap(packet_id_32);

        // calculate nonce, which is pktid + nonce_tail
        RtlCopyMemory(nonce, &packet_id_net, 4);
        RtlCopyMemory(nonce + 4, tx->Key.ImplicitIV + 4, 8);

        // prepend with pktid
        RtlCopyMemory(buf + OVPN_DATA_V2_LEN, &packet_id_net, sizeof(packet_id_net));
    }

    // update number of plaintext blocks encrypted. Use the (x + (n-1))/n trick to round up the result to the number of blocks used
    const ULONGLONG blocksize = AEAD_LIMIT_BLOCKSIZE;
    ULONGLONG inc = ((ULONGLONG)len + (blocksize - 1)) / blocksize;
    tx->Key.PlaintextBlocks += inc;

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
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptEncrypt(tx->Key.Key, buf, (ULONG)len, &authInfo, NULL, 0, buf, (ULONG)len, &bytesDone, 0));

done:
    return status;
}

static VOID
OvpnCryptoDescribeLayout(BOOLEAN aead, BOOLEAN useEpoch, OvpnCryptoPacketLayout* layout)
{
    layout->FrontLen = OVPN_DATA_V2_LEN + 4;
    layout->TailLen = 0;

    if (aead) {
        layout->FrontLen = OVPN_DATA_V2_LEN + (useEpoch ? 8 : 4);
        if (!useEpoch) {
            layout->FrontLen += AEAD_AUTH_TAG_LEN;
        }

        layout->TailLen = useEpoch ? AEAD_AUTH_TAG_LEN : 0;
    }
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoNewKey(OvpnPeerContext* peer, POVPN_CRYPTO_DATA_V2 cryptoDataV2, BCRYPT_ALG_HANDLE algHandle, BCRYPT_ALG_HANDLE hkdfAlgHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVPN_CRYPTO_DATA cryptoData = &cryptoDataV2->V1;

    BOOLEAN primary;
    if (cryptoData->KeySlot == OVPN_KEY_SLOT::OVPN_KEY_SLOT_PRIMARY) {
        primary = TRUE;
    }
    else if (cryptoData->KeySlot == OVPN_KEY_SLOT::OVPN_KEY_SLOT_SECONDARY) {
        primary = FALSE;
    }
    else {
        LOG_ERROR("Invalid key slot", TraceLoggingValue((int)cryptoData->KeySlot, "keySlot"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    BOOLEAN aead;
    if ((cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM) || (cryptoData->CipherAlg == OVPN_CIPHER_ALG_CHACHA20_POLY1305)) {
        aead = TRUE;
    }
    else if (cryptoData->CipherAlg == OVPN_CIPHER_ALG_NONE) {
        aead = FALSE;
    }
    else {
        LOG_ERROR("Unknown OVPN_CIPHER_ALG", TraceLoggingValue((int)cryptoData->CipherAlg, "CipherAlg"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (aead && ((cryptoData->Encrypt.KeyLen > 32) || (cryptoData->Decrypt.KeyLen > 32))) {
        LOG_ERROR("Incorrect encrypt or decrypt key length", TraceLoggingValue(cryptoData->Encrypt.KeyLen, "Encrypt.KeyLen"),
            TraceLoggingValue(cryptoData->Decrypt.KeyLen, "Decrypt.KeyLen"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // derive with no lock held; key derivation is too slow for the data path to spin on
    OvpnCryptoTxState tx;
    OvpnCryptoRxState rx;
    OvpnCryptoOptions options;
    OvpnCryptoPacketLayout layout;
    RtlZeroMemory(&tx, sizeof(tx));
    RtlZeroMemory(&rx, sizeof(rx));
    RtlZeroMemory(&options, sizeof(options));

    if (aead) {
        options.KeyLen = cryptoData->Encrypt.KeyLen;

        if (cryptoDataV2->CryptoOptions & CRYPTO_OPTIONS_EPOCH) {
            options.AeadUsageLimit = OvpnCryptoAeadUsageLimit(cryptoData->CipherAlg);
#if DBG
            if (g_OvpnTestAeadUsageLimit != 0) {
                if ((options.AeadUsageLimit == 0) || (g_OvpnTestAeadUsageLimit < options.AeadUsageLimit)) {
                    options.AeadUsageLimit = g_OvpnTestAeadUsageLimit;
                }
            }
#endif
            options.UseEpoch = TRUE;
            options.HkdfAlgHandle = hkdfAlgHandle;
            options.AeadAlgHangle = algHandle;

            tx.EpochKey.Epoch = 1;
            RtlCopyMemory(tx.EpochKey.EpochKey, cryptoData->Encrypt.Key, 32);
            OvpnCryptoEpochInitKey(&tx.Key, &tx.EpochKey, &options);

            rx.EpochKey.Epoch = 1;
            RtlCopyMemory(rx.EpochKey.EpochKey, cryptoData->Decrypt.Key, 32);
            OvpnCryptoEpochInitKey(&rx.Key, &rx.EpochKey, &options);
            OvpnCryptoEpochGenerateFutureRecvKeys(&rx, &options);
        }
        else {
            // generate keys from key materials
            GOTO_IF_NOT_NT_SUCCESS(fail, status, BCryptGenerateSymmetricKey(algHandle, &tx.Key.Key, NULL, 0, cryptoData->Encrypt.Key, cryptoData->Encrypt.KeyLen, 0));
            GOTO_IF_NOT_NT_SUCCESS(fail, status, BCryptGenerateSymmetricKey(algHandle, &rx.Key.Key, NULL, 0, cryptoData->Decrypt.Key, cryptoData->Decrypt.KeyLen, 0));

            // copy nonce tails
            RtlCopyMemory(tx.Key.ImplicitIV + 4, cryptoData->Encrypt.NonceTail, sizeof(cryptoData->Encrypt.NonceTail));
            RtlCopyMemory(rx.Key.ImplicitIV + 4, cryptoData->Decrypt.NonceTail, sizeof(cryptoData->Decrypt.NonceTail));
        }

        LOG_INFO("New key", TraceLoggingValue(cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM ? "aes-gcm" : "chacha20-poly1305", "alg"),
            TraceLoggingValue(cryptoData->KeyId, "KeyId"), TraceLoggingValue(cryptoData->PeerId, "PeerId"));
    }
    else {
        LOG_INFO("Using cipher none");
    }

    tx.KeyId = cryptoData->KeyId;
    tx.PeerId = cryptoData->PeerId;
    rx.KeyId = cryptoData->KeyId;

    OvpnCryptoDescribeLayout(aead, options.UseEpoch, &layout);

    OvpnCryptoContext* cryptoContext = &peer->CryptoContext;
    KIRQL irql;

    // install the send side
    KeAcquireSpinLock(&peer->TxLock, &irql);
    {
        OvpnCryptoTxState* slot = primary ? &cryptoContext->Tx.Primary : &cryptoContext->Tx.Secondary;
        OvpnCryptoEpochUninitTx(slot);
        RtlCopyMemory(slot, &tx, sizeof(tx));

        cryptoContext->Tx.Encrypt = aead ? OvpnCryptoEncryptAEAD : OvpnCryptoEncryptNone;
        cryptoContext->Tx.Options = options;
        cryptoContext->Tx.Layout = layout;
    }
    KeReleaseSpinLock(&peer->TxLock, irql);

    // install the receive side; UninitRx also drops the old future and retiring keys
    KeAcquireSpinLock(&peer->RxLock, &irql);
    {
        OvpnCryptoRxState* slot = primary ? &cryptoContext->Rx.Primary : &cryptoContext->Rx.Secondary;
        OvpnCryptoEpochUninitRx(slot);
        RtlCopyMemory(slot, &rx, sizeof(rx));

        cryptoContext->Rx.Decrypt = aead ? OvpnCryptoDecryptAEAD : OvpnCryptoDecryptNone;
        cryptoContext->Rx.Options = options;
        cryptoContext->Rx.Layout = layout;
    }
    KeReleaseSpinLock(&peer->RxLock, irql);

    // scrub the local key material; the handles now belong to the peer
    RtlSecureZeroMemory(&tx, sizeof(tx));
    RtlSecureZeroMemory(&rx, sizeof(rx));

    return STATUS_SUCCESS;

fail:
    OvpnCryptoEpochUninitTx(&tx);
    OvpnCryptoEpochUninitRx(&rx);
    return status;
}

_Use_decl_annotations_
VOID
OvpnCryptoSwapKeys(OvpnPeerContext* peer)
{
    OvpnCryptoContext* cryptoContext = &peer->CryptoContext;
    KIRQL irql;

    // one direction at a time; the receive path looks keys up by id, so the gap does not matter
    KeAcquireSpinLock(&peer->TxLock, &irql);
    {
        OvpnCryptoTxState tmp = cryptoContext->Tx.Primary;
        cryptoContext->Tx.Primary = cryptoContext->Tx.Secondary;
        cryptoContext->Tx.Secondary = tmp;
        RtlSecureZeroMemory(&tmp, sizeof(tmp));
    }
    KeReleaseSpinLock(&peer->TxLock, irql);

    KeAcquireSpinLock(&peer->RxLock, &irql);
    {
        OvpnCryptoRxState tmp = cryptoContext->Rx.Primary;
        cryptoContext->Rx.Primary = cryptoContext->Rx.Secondary;
        cryptoContext->Rx.Secondary = tmp;
        RtlSecureZeroMemory(&tmp, sizeof(tmp));
    }
    KeReleaseSpinLock(&peer->RxLock, irql);

    LOG_INFO("Key swapped", TraceLoggingValue(cryptoContext->Tx.Primary.KeyId, "key1"), TraceLoggingValue(cryptoContext->Tx.Secondary.KeyId, "key2"));
}

_Use_decl_annotations_
VOID
OvpnCryptoUninit(OvpnCryptoContext* cryptoContext)
{
    OvpnCryptoEpochUninitTx(&cryptoContext->Tx.Primary);
    OvpnCryptoEpochUninitTx(&cryptoContext->Tx.Secondary);
    OvpnCryptoEpochUninitRx(&cryptoContext->Rx.Primary);
    OvpnCryptoEpochUninitRx(&cryptoContext->Rx.Secondary);

    RtlZeroMemory(cryptoContext, sizeof(OvpnCryptoContext));
}
