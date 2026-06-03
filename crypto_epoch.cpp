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

#include "crypto_epoch.h"
#include "trace.h"

// Derive bytes via HKDF-Expand with PRK = E_i, using bcrypt HKDF.
// info = OvpnMakeLabel(L, label)
_Use_decl_annotations_
NTSTATUS OvpnCryptoExpandLabel(
    BCRYPT_ALG_HANDLE hkdfAlg,
    const UCHAR* E_i,       // PRK (32 bytes for SHA-256)
    USHORT outLen,          // bytes to derive
    const char* label,      // "data_key" / "data_iv" / "datakey upd"
    UCHAR* outBytes
)
{
    NTSTATUS status = STATUS_SUCCESS;

    BCRYPT_KEY_HANDLE hKey = NULL;

    // create key handle with PRK bytes
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(hkdfAlg, &hKey, NULL, 0, (PUCHAR)E_i, 32, 0));

    // select SHA-256
    // BCRYPT_SHA256_ALGORITHM is a wide literal; sizeof(..) includes the NUL in bytes.
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(hKey, BCRYPT_HKDF_HASH_ALGORITHM, (PUCHAR)BCRYPT_SHA256_ALGORITHM, (ULONG)sizeof(BCRYPT_SHA256_ALGORITHM), 0));

    // tell HKDF we're already supplying the PRK in the key handle:
    // passing NULL,0 just switches to "PRK is finalized" mode.
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(hKey, BCRYPT_HKDF_PRK_AND_FINALIZE, NULL, 0, 0));

    // build info = OvpnLabel(outLen, "data_key"/"data_iv")
    UCHAR info[2 + 1 + 64 + 1 + 255]; // enough for our labels
    ULONG infoLen = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoMakeLabel(info, (ULONG)sizeof(info), &infoLen, outLen, label));

    // prepare KDF params
    BCryptBuffer infoBuf;
    BCryptBufferDesc desc;

    RtlZeroMemory(&infoBuf, sizeof(infoBuf));
    RtlZeroMemory(&desc, sizeof(desc));

    infoBuf.cbBuffer = infoLen;
    infoBuf.BufferType = KDF_HKDF_INFO;
    infoBuf.pvBuffer = info;

    desc.ulVersion = BCRYPTBUFFER_VERSION;
    desc.cBuffers = 1;
    desc.pBuffers = &infoBuf;

    // derive
    ULONG got = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptKeyDerivation(hKey, &desc, outBytes, outLen, &got, 0));
    if (got != outLen) {
        status = STATUS_INTERNAL_ERROR;
    }

done:
    if (hKey) BCryptDestroyKey(hKey);
    return status;
}

// Build TLS 1.3-style label with "ovpn " prefix, into caller buffer.
// struct {
//   uint16 length = L;
//   opaque label<6..255> = "ovpn " + Label;
//   opaque context<0..255>;
// } OvpnLabel;
_Use_decl_annotations_
NTSTATUS OvpnCryptoMakeLabel(
    UCHAR* out,
    ULONG cbOut,
    ULONG* pcbWritten,
    USHORT L,
    const char* label)
{
    NTSTATUS status = STATUS_SUCCESS;

    static const char prefix[] = "ovpn ";

    const size_t prefixLen = sizeof(prefix) - 1;
    size_t labelLen = 0;

    GOTO_IF_NOT_NT_SUCCESS(done, status, RtlStringCbLengthA(label, 256, &labelLen)); // labels are tiny, 256 is safe

    *pcbWritten = 0;

    // Total encoded label length = "ovpn " + label
    size_t totalLabelLen = prefixLen + labelLen;
    if (totalLabelLen < 6 || totalLabelLen > 255) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    // total = 2(length) + 1(totalLabelLen) + totalLabelLen + 1(ctxLen=0)
    ULONG need = 2 + 1 + (ULONG)totalLabelLen + 1;
    if (cbOut < need) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto done;
    }

    ULONG p = 0;
    out[p++] = (UCHAR)(L >> 8);
    out[p++] = (UCHAR)(L & 0xFF);
    out[p++] = (UCHAR)totalLabelLen;

    // "ovpn "
    RtlCopyMemory(out + p, prefix, prefixLen);
    p += (ULONG)prefixLen;


    // Label
    RtlCopyMemory(out + p, label, labelLen);
    p += (ULONG)labelLen;

    // context length = 0
    out[p++] = 0;

    *pcbWritten = p;

done:
    return status;
}

VOID
OvpnCryptoEpochInitKey(OvpnCryptoKeyContext* ctx, OvpnCryptoEpochKey* epochKey, OvpnCryptoOptions* opts)
{
    LOG_INFO("Epoch Data Key", TraceLoggingValue(epochKey->Epoch, "epoch"));

    OvpnCryptoKeyParameters key{0};
    OvpnCryptoEpochDataKeyDerive(&key, epochKey, opts->HkdfAlgHandle, opts->AeadAlgHangle, opts->KeyLen);
    ctx->Epoch = key.Epoch;
    ctx->Key = key.KeyHandle;
    RtlCopyMemory(ctx->ImplicitIV, key.IV, sizeof(ctx->ImplicitIV));

    RtlSecureZeroMemory(&key, sizeof(OvpnCryptoKeyParameters));
}

NTSTATUS
OvpnCryptoEpochDataKeyDerive(OvpnCryptoKeyParameters* key, OvpnCryptoEpochKey* epochKey, BCRYPT_ALG_HANDLE hkdfAlgHandle, BCRYPT_ALG_HANDLE algHandle, UCHAR cipherSize)
{
    NTSTATUS status;

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoExpandLabel(hkdfAlgHandle, epochKey->EpochKey, cipherSize, "data_key", key->Cipher));
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(algHandle, &key->KeyHandle, NULL, 0, key->Cipher, cipherSize, 0));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoExpandLabel(hkdfAlgHandle, epochKey->EpochKey, 12, "data_iv", key->IV));

    key->Epoch = epochKey->Epoch;

done:
    return status;
}

VOID
OvpnCryptoEpochKeyIterate(OvpnCryptoEpochKey* epochKey, BCRYPT_ALG_HANDLE hkdfAlgHandle)
{
    ++epochKey->Epoch;
    OvpnCryptoExpandLabel(hkdfAlgHandle, epochKey->EpochKey, sizeof(epochKey->EpochKey), "datakey upd", epochKey->EpochKey);
}

VOID
OvpnCryptoEpochGenerateFutureRecvKeys(OvpnCryptoKeySlot* keySlot, OvpnCryptoOptions* opts)
{
    UINT16 currentDecryptEpoch = keySlot->Decrypt.Epoch;

    // free unused keys
    for (int i = 0; i < FUTURE_EPOCH_KEYS_COUNT; ++i) {
        auto key = &keySlot->FutureEpochKeys[i];
        if ((key->Epoch > 0) && (key->Epoch < currentDecryptEpoch)) {
            BCryptDestroyKey(key->Key);
            RtlZeroMemory(key, sizeof(*key));
        }
    }

    // Highest generated epoch comes from EpochKeyRecv, like userspace
    // (crypto_epoch.c:235). Reading the last future-key slot instead breaks
    // when that slot is consumed/zeroed, overshooting numKeysGenerate.
    UINT16 currentHighestKey = keySlot->EpochKeyRecv.Epoch;
    UINT16 desiredHighestKey = currentDecryptEpoch + FUTURE_EPOCH_KEYS_COUNT;
    UINT16 numKeysGenerate = desiredHighestKey - currentHighestKey;

    RtlMoveMemory(keySlot->FutureEpochKeys, &keySlot->FutureEpochKeys[numKeysGenerate], (FUTURE_EPOCH_KEYS_COUNT - numKeysGenerate) * sizeof(OvpnCryptoKeyContext));

    for (int i = 16 - numKeysGenerate; i < FUTURE_EPOCH_KEYS_COUNT; ++i)
    {
        RtlSecureZeroMemory(&keySlot->FutureEpochKeys[i], sizeof(OvpnCryptoKeyContext));

        OvpnCryptoEpochKeyIterate(&keySlot->EpochKeyRecv, opts->HkdfAlgHandle);
        OvpnCryptoEpochInitKey(&keySlot->FutureEpochKeys[i], &keySlot->EpochKeyRecv, opts);
    }
}

VOID
OvpnCryptoEpochReplaceUpdateRecvKey(OvpnCryptoKeySlot* keySlot, UINT16 new_epoch, OvpnCryptoOptions* opts)
{
    // Find the key of the new epoch in future keys
    UINT16 fki;
    for (fki = 0; fki < FUTURE_EPOCH_KEYS_COUNT; fki++) {
        if (keySlot->FutureEpochKeys[fki].Epoch == new_epoch) {
            break;
        }
    }

    // Callers only reach this with an AEAD-authenticated future epoch, so the
    // key is always present. Guard the not-found case anyway: without it fki
    // would be FUTURE_EPOCH_KEYS_COUNT and the ctx below would point one past
    // the array, type-confusing PktidRecvRetiring as a key context on the
    // *ctx read and the RtlZeroMemory write. Userspace ASSERTs here; we can't
    // (release builds compile it out), so bail explicitly.
    if (fki == FUTURE_EPOCH_KEYS_COUNT) {
        LOG_ERROR("New epoch not found in future keys", TraceLoggingValue(new_epoch, "epoch"));
        return;
    }

    OvpnCryptoKeyContext* ctx = &keySlot->FutureEpochKeys[fki];

    // Check if the new recv key epoch is higher than the send key epoch. If yes we will replace the send key as well
    if (keySlot->Encrypt.Epoch < new_epoch) {
        BCryptDestroyKey(keySlot->Encrypt.Key);
        RtlZeroMemory(&keySlot->Encrypt, sizeof(OvpnCryptoKeyContext));

        // Update the epoch_key for send to match the current key being used
        while (keySlot->EpochKeySend.Epoch < new_epoch) {
            OvpnCryptoEpochKeyIterate(&keySlot->EpochKeySend, opts->HkdfAlgHandle);
        }
        OvpnCryptoEpochInitKey(&keySlot->Encrypt, &keySlot->EpochKeySend, opts);
    }

    // Replace receive key
    BCryptDestroyKey(keySlot->RetiringEpochDataReceiveKey.Key);
    RtlZeroMemory(&keySlot->RetiringEpochDataReceiveKey, sizeof(OvpnCryptoKeyContext));

    keySlot->RetiringEpochDataReceiveKey = keySlot->Decrypt;

    // Carry the replay window forward with the key it polices: the current
    // PktidRecv becomes the retiring window so already-seen packet IDs under
    // the old key cannot be replayed during the grace period. Mirrors
    // packet_id_move_recv() in userspace OpenVPN (src/openvpn/crypto_epoch.c).
    keySlot->PktidRecvRetiring = keySlot->PktidRecv;
    RtlZeroMemory(&keySlot->PktidRecv, sizeof(keySlot->PktidRecv));

    keySlot->Decrypt = *ctx;

    RtlZeroMemory(ctx, sizeof(*ctx));

    // Generate new future keys
    OvpnCryptoEpochGenerateFutureRecvKeys(keySlot, opts);
}

OvpnCryptoKeyContext*
OvpnCryptoEpochLookupDecryptKey(OvpnCryptoKeySlot* keySlot, UINT16 epoch)
{
    /* Current decrypt key is the most likely one */
    if (keySlot->Decrypt.Epoch == epoch) {
        return &keySlot->Decrypt;
    }
    else if (keySlot->RetiringEpochDataReceiveKey.Epoch && keySlot->RetiringEpochDataReceiveKey.Epoch == epoch) {
        return &keySlot->RetiringEpochDataReceiveKey;
    }
    else if (epoch > keySlot->Decrypt.Epoch && epoch <= keySlot->Decrypt.Epoch + FUTURE_EPOCH_KEYS_COUNT) {
        // Key in the range of future keys
        int index = epoch - (keySlot->Decrypt.Epoch + 1);

        if (epoch > (UINT16_MAX - FUTURE_EPOCH_KEYS_COUNT - 1)) {
            return NULL;
        }
        else {
            return &keySlot->FutureEpochKeys[index];
        }
    }
    else {
        return NULL;
    }
}

VOID
OvpnCryptoMakeEpochNonce(UCHAR* epochIv, UINT64 packet_id_net, UCHAR* nonce)
{
    // first 8 bytes of IV (aka nonce) is pktid_net XOR 8 bytes of epoch's implicit IV
    UINT64 iv0;
    RtlCopyMemory(&iv0, epochIv, sizeof(iv0));
    iv0 ^= packet_id_net;
    RtlCopyMemory(nonce, &iv0, sizeof(iv0));

    // last 4 bytes of IV are from epoch's implicit IV
    RtlCopyMemory(nonce + 8, epochIv + 8, 4);
}

VOID
OvpnCryptoEpochIterateSendKey(OvpnCryptoKeySlot* keySlot, OvpnCryptoOptions* opts)
{
    OvpnCryptoEpochKeyIterate(&keySlot->EpochKeySend, opts->HkdfAlgHandle);

    BCryptDestroyKey(keySlot->Encrypt.Key);
    RtlSecureZeroMemory(&keySlot->Encrypt, sizeof(OvpnCryptoKeyContext));
    OvpnCryptoEpochInitKey(&keySlot->Encrypt, &keySlot->EpochKeySend, opts);

    RtlZeroMemory(&keySlot->PktidXmit, sizeof(keySlot->PktidXmit));
}

VOID
OvpnCryptoEpochUninitSlot(OvpnCryptoKeySlot* slot)
{
    if (slot->Encrypt.Key) {
        BCryptDestroyKey(slot->Encrypt.Key);
    }
    for (int i = 0; i < FUTURE_EPOCH_KEYS_COUNT; ++i) {
        if (slot->FutureEpochKeys[i].Key) {
            BCryptDestroyKey(slot->FutureEpochKeys[i].Key);
        }
    }
    if (slot->RetiringEpochDataReceiveKey.Key) {
        BCryptDestroyKey(slot->RetiringEpochDataReceiveKey.Key);
    }
    RtlSecureZeroMemory(slot, sizeof(OvpnCryptoKeySlot));
}