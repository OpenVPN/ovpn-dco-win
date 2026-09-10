#include <gtest/gtest.h>
#include <memory>

/* notifyqueue.h must precede crypto_epoch.h: the former pulls <winsock2.h>
 * (via uapi/ovpn-dco.h) which must be included before <windows.h> brings in
 * the legacy <winsock.h>. crypto_epoch.h includes <windows.h> first. */
#include "../notifyqueue.h"
#include "../peerstats.h"
#include "../crypto_epoch.h"

class CryptoTest : public testing::Test
{
protected:
    void SetUp() override
    {
        RtlZeroMemory(&opts, sizeof(opts));
        RtlZeroMemory(&keySlot, sizeof(keySlot));

        opts.KeyLen = 32;
        opts.UseEpoch = 1;

        ASSERT_EQ(BCryptOpenAlgorithmProvider(&opts.HkdfAlgHandle, BCRYPT_HKDF_ALGORITHM, NULL, 0), STATUS_SUCCESS);
        ASSERT_EQ(BCryptOpenAlgorithmProvider(&opts.AeadAlgHangle, BCRYPT_AES_ALGORITHM, NULL, 0), STATUS_SUCCESS);

        keySlot.EpochKeySend.Epoch = 1;
        keySlot.EpochKeyRecv.Epoch = 1;

        OvpnCryptoEpochInitKey(&keySlot.Encrypt, &keySlot.EpochKeySend, &opts);
        OvpnCryptoEpochInitKey(&keySlot.Decrypt, &keySlot.EpochKeyRecv, &opts);

        RtlZeroMemory(keySlot.FutureEpochKeys, sizeof(keySlot.FutureEpochKeys));
        OvpnCryptoEpochGenerateFutureRecvKeys(&keySlot, &opts);
    }

    OvpnCryptoOptions opts;
    OvpnCryptoKeySlot keySlot;
};

TEST_F(CryptoTest, HkdfExpand) {
    uint8_t secret[32] = { 0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f,
                           0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f,
                           0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5 };

    const char* label = "unit test";

    uint8_t out_expected[16] = { 0x18, 0x5e, 0xaa, 0x1c, 0x7f, 0x22, 0x8a, 0xb8,
                                 0xeb, 0x29, 0x77, 0x32, 0x14, 0xd9, 0x20, 0x46 };

    uint8_t out[16];

    ASSERT_EQ(OvpnCryptoExpandLabel(opts.HkdfAlgHandle, secret, sizeof(out), label, out), STATUS_SUCCESS);
    ASSERT_EQ(0, std::memcmp(out, out_expected, sizeof(out)));
}

/* The epoch tests below are written in terms of FUTURE_EPOCH_KEYS_COUNT (N)
 * so they keep tracking the window size. Fixture state: Decrypt.Epoch == 1,
 * future keys span 2..1+N, EpochKeyRecv.Epoch == 1+N. */
static constexpr int N = FUTURE_EPOCH_KEYS_COUNT;

TEST_F(CryptoTest, EpochKeyGeneration) {
    // check that the keys look like expected
    ASSERT_EQ(keySlot.FutureEpochKeys[0].Epoch, 2);
    ASSERT_EQ(keySlot.FutureEpochKeys[N - 1].Epoch, 1 + N);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, 1);
    ASSERT_EQ(keySlot.EpochKeyRecv.Epoch, 1 + N);

    // Now replace the recv key with a future key from the middle of the window
    const int slot = N / 2;
    const UINT16 epoch = 2 + slot;
    BCryptDestroyKey(keySlot.Decrypt.Key);
    RtlZeroMemory(&keySlot.Decrypt, sizeof(keySlot.Decrypt));
    ASSERT_EQ(keySlot.FutureEpochKeys[slot].Epoch, epoch);
    keySlot.Decrypt = keySlot.FutureEpochKeys[slot];
    RtlZeroMemory(&keySlot.FutureEpochKeys[slot], sizeof(OvpnCryptoKeyContext));

    OvpnCryptoEpochGenerateFutureRecvKeys(&keySlot, &opts);
    ASSERT_EQ(keySlot.FutureEpochKeys[0].Epoch, epoch + 1);
    ASSERT_EQ(keySlot.FutureEpochKeys[N - 1].Epoch, epoch + N);
    ASSERT_EQ(keySlot.EpochKeyRecv.Epoch, epoch + N);
}

TEST_F(CryptoTest, EpochKeyRotateToHighestFutureKey) {
    /* Rotating to the highest future epoch (Decrypt + N) is a legitimate
     * protocol fast-forward, but it consumes and zeroes the last future key.
     * GenerateFutureRecvKeys used to read a zeroed highestFutureKey, collapsed
     * currentHighestKey to 1, and computed numKeysGenerate = 2N -- turning the
     * RtlMoveMemory into an out-of-bounds copy and the regen loop into
     * negative-index writes. Pre-fix this crashes; post-fix the whole window
     * regenerates to 2+N..1+2N. */
    ASSERT_EQ(keySlot.FutureEpochKeys[N - 1].Epoch, 1 + N);

    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 1 + N, &opts);

    ASSERT_EQ(keySlot.Decrypt.Epoch, 1 + N);
    ASSERT_EQ(keySlot.FutureEpochKeys[0].Epoch, 2 + N);
    ASSERT_EQ(keySlot.FutureEpochKeys[N - 1].Epoch, 1 + 2 * N);
}

TEST_F(CryptoTest, EpochKeyRegeneratesFullWindowAfterRotation) {
    /* Every slot must hold a live key with the expected epoch after a
     * rotation. Catches a regen loop whose start index is not derived from
     * FUTURE_EPOCH_KEYS_COUNT (it used to hardcode 16): with a smaller window
     * the loop would not execute at all and the window would silently go
     * stale after the first rotation. */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 2, &opts);

    for (int i = 0; i < N; ++i) {
        ASSERT_EQ(keySlot.FutureEpochKeys[i].Epoch, 3 + i) << "slot " << i;
        ASSERT_NE(keySlot.FutureEpochKeys[i].Key, nullptr) << "slot " << i;
    }
    ASSERT_EQ(keySlot.EpochKeyRecv.Epoch, 2 + N);
}

TEST_F(CryptoTest, EpochKeyRotation) {
    /* should replace send + key recv */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, N, &opts);

    ASSERT_EQ(keySlot.Decrypt.Epoch, N);
    ASSERT_EQ(keySlot.Encrypt.Epoch, N);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, N);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, 1);

    /* Iterate the data send key N times to get it to 2N */
    for (int i = 0; i < N; i++)
    {
        OvpnCryptoEpochKeyIterate(&keySlot.EpochKeySend, opts.HkdfAlgHandle);

        BCryptDestroyKey(keySlot.Encrypt.Key);
        RtlZeroMemory(&keySlot.Encrypt, sizeof(OvpnCryptoKeyContext));

        OvpnCryptoEpochInitKey(&keySlot.Encrypt, &keySlot.EpochKeySend, &opts);
    }
    ASSERT_EQ(keySlot.Encrypt.Epoch, 2 * N);

    /* recv epochs below the send epoch must leave the send side alone */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, N + 1, &opts);
    ASSERT_EQ(keySlot.Decrypt.Epoch, N + 1);
    ASSERT_EQ(keySlot.Encrypt.Epoch, 2 * N);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, 2 * N);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, N);

    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 2 * N - 1, &opts);
    ASSERT_EQ(keySlot.Decrypt.Epoch, 2 * N - 1);
    ASSERT_EQ(keySlot.Encrypt.Epoch, 2 * N);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, 2 * N);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, N + 1);

    OvpnCryptoEpochKeyIterate(&keySlot.EpochKeySend, opts.HkdfAlgHandle);

    BCryptDestroyKey(keySlot.Encrypt.Key);
    RtlZeroMemory(&keySlot.Encrypt, sizeof(OvpnCryptoKeyContext));

    OvpnCryptoEpochInitKey(&keySlot.Encrypt, &keySlot.EpochKeySend, &opts);

    ASSERT_EQ(keySlot.Encrypt.Epoch, 2 * N + 1);
}

TEST_F(CryptoTest, EpochKeyReceiveLookup)
{
    /* lookup some wacky things that should fail */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 2000), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, -1), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 0xefff), nullptr);

    /* Lookup the edges of the current window: 1 active, 2..1+N future */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 0), nullptr);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, 0);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1)->Epoch, 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 2)->Epoch, 2);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, N)->Epoch, N);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1 + N)->Epoch, 1 + N);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 2 + N), nullptr);

    /* Should move 1 to retiring key but leave 2..a-1 undefined, a as
     * active and a+1..a+N as future keys */
    const UINT16 a = 1 + N / 2;
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, a, &opts);

    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 0), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1)->Epoch, 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1), &keySlot.RetiringEpochDataReceiveKey);

    for (UINT16 e = 2; e < a; ++e) {
        ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, e), nullptr) << "epoch " << e;
    }
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a)->Epoch, a);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N - 1)->Epoch, a + N - 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N)->Epoch, a + N);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N + 1), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N + 2), nullptr);

    /* Should move a to retiring key and have a+1 as active key and
     * a+2..a+1+N as future keys */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, a + 1, &opts);
    for (UINT16 e = 0; e < a; ++e) {
        ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, e), nullptr) << "epoch " << e;
    }
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a)->Epoch, a);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a), &keySlot.RetiringEpochDataReceiveKey);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + 1)->Epoch, a + 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N)->Epoch, a + N);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N + 1)->Epoch, a + N + 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N + 2), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, a + N + 3), nullptr);
}

TEST_F(CryptoTest, EpochKeyOverflow)
{
    /* Modify the receive epoch and keys to have a very high epoch to test
     * the end of array. Iterating through all 65k keys takes a 2-3s, so we
     * avoid this for the unit test.
     *
     * Lookup refuses any epoch above UINT16_MAX - N - 1, because rotating to
     * it would need future keys past UINT16_MAX. Start two epochs below that
     * limit so both the accepted and the refused edges are in the window. */
    const UINT16 highest = UINT16_MAX - N - 1;
    const UINT16 start = highest - 2;

    keySlot.Decrypt.Epoch = start;
    keySlot.Encrypt.Epoch = start;

    keySlot.EpochKeySend.Epoch = start;
    keySlot.EpochKeyRecv.Epoch = start + N;

    for (int i = 0; i < N; ++i) {
        keySlot.FutureEpochKeys[i].Epoch = start + 1 + i;
    }

    /* Looking up these keys should still work as they will not break the
     * limit when generating keys */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, highest - 1)->Epoch, highest - 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, highest)->Epoch, highest);

    /* This key is no longer eligible for decrypting as the N future keys
     * would be larger than uint16_t maximum */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX - N), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX), nullptr);

    /* Check that moving to the last possible epoch works */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, highest, &opts);
    ASSERT_EQ(keySlot.EpochKeyRecv.Epoch, UINT16_MAX - 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, highest)->Epoch, highest);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX - N), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX), nullptr);
}

TEST_F(CryptoTest, EpochKeyRotationCarriesReplayWindow)
{
    /* Seed PktidRecv with non-trivial state, simulating that some packets
     * have already been accepted under the current decrypt epoch. After
     * OvpnCryptoEpochReplaceUpdateRecvKey rotates, this state MUST move to
     * PktidRecvRetiring -- otherwise captured retiring-epoch packets become
     * replayable through the empty (zero-initialised) retiring window.
     *
     * Mirrors userspace OpenVPN packet_id_move_recv() at
     * src/openvpn/crypto_epoch.c:325 which is invoked from
     * epoch_replace_update_recv_key right between the key promotion lines.
     */
    OvpnPktidRecv before = {};
    before.Id       = 0x0000000000000042ULL;
    before.IdFloor  = 0x0000000000000040ULL;
    before.Base     = 7;
    before.Extent   = 100;
    before.History[0] = 0xFF;
    before.History[7] = 0x55;
    before.Expire.QuadPart = 1234567;

    keySlot.PktidRecv = before;

    /* Sanity: retiring window starts at zero (set up by SetUp). */
    OvpnPktidRecv zero = {};
    ASSERT_EQ(0, std::memcmp(&keySlot.PktidRecvRetiring, &zero, sizeof(zero)));

    /* Rotate from epoch 1 -> epoch 2. */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 2, &opts);

    /* Security-critical: PktidRecvRetiring MUST inherit the previous current
     * window. Without this, any captured packet from epoch 1 will be
     * accepted at least once under the retiring key because PktidRecvRetiring
     * is still all-zero (Id=0, IdFloor=0, empty History). */
    ASSERT_EQ(0, std::memcmp(&keySlot.PktidRecvRetiring, &before, sizeof(before)))
        << "PktidRecvRetiring did not inherit PktidRecv state after rotation; "
           "captured retiring-epoch packets are replayable.";

    /* Functionally redundant given the wire format embeds the epoch in the
     * high bits of the 64-bit pktid (the auto-rebase in OvpnPktidRecvVerify
     * handles the transition), but matches userspace and prevents stale state
     * from leaking forward if the wire format ever changes. */
    ASSERT_EQ(0, std::memcmp(&keySlot.PktidRecv, &zero, sizeof(zero)))
        << "PktidRecv was not reset on rotation.";
}

TEST_F(CryptoTest, EpochDeriveDataKey)
{
    OvpnCryptoKeyParameters kp;
    OvpnCryptoEpochKey e17{ {19, 12}, 17};
    OvpnCryptoEpochDataKeyDerive(&kp, &e17, opts.HkdfAlgHandle, opts.AeadAlgHangle, 24);

    uint8_t exp_cipherkey[24] = { 0xed, 0x85, 0x33, 0xdb, 0x1c, 0x28, 0xac, 0xe4,
                              0x18, 0xe9, 0x00, 0x6a, 0xb2, 0x9c, 0x17, 0x41,
                              0x7d, 0x60, 0xeb, 0xe6, 0xcd, 0x90, 0xbf, 0x0a };

    uint8_t exp_impl_iv[12] = { 0x86, 0x89, 0x0a, 0xab, 0xf0, 0x32,
                                0xcb, 0x59, 0xf4, 0xcf, 0xa3, 0x4e };

    ASSERT_EQ(0, std::memcmp(kp.Cipher, exp_cipherkey, sizeof(exp_cipherkey)));
    ASSERT_EQ(0, std::memcmp(kp.IV, exp_impl_iv, sizeof(exp_impl_iv)));
}

/* Regression coverage for the FillDelPeerEvent / FillFloatPeerEvent helpers
 * used to populate the IRP system buffer for OVPN_IOCTL_NOTIFY_EVENT.
 *
 * The buffer returned by WdfRequestRetrieveOutputBuffer aliases a
 * METHOD_BUFFERED system buffer that the I/O Manager does NOT zero. Any
 * byte the helper fails to overwrite is copied to user mode as raw
 * non-paged pool. Poison the buffer first; the helper must leave only
 * field-controlled bytes and zeros. */

static OVPN_NOTIFY_EVENT MakePoisonedEvent()
{
    OVPN_NOTIFY_EVENT evt;
    std::memset(&evt, 0xAB, sizeof(evt));
    return evt;
}

TEST(NotifyEventFill, DelPeerLeavesNoPoolResidue)
{
    OVPN_NOTIFY_EVENT evt = MakePoisonedEvent();

    NotifyQueue::FillDelPeerEvent(&evt, 42, OVPN_DEL_PEER_REASON_EXPIRED);

    ASSERT_EQ(evt.Cmd, OVPN_CMD_DEL_PEER);
    ASSERT_EQ(evt.PeerId, 42);
    ASSERT_EQ(evt.DelPeerReason, OVPN_DEL_PEER_REASON_EXPIRED);

    /* FloatAddress is not meaningful for OVPN_CMD_DEL_PEER and must be
     * zero -- otherwise userspace gets ~128 bytes of pool residue plus
     * the 4-byte alignment hole between DelPeerReason and FloatAddress. */
    OVPN_NOTIFY_EVENT zero;
    std::memset(&zero, 0, sizeof(zero));
    ASSERT_EQ(0, std::memcmp(&evt.FloatAddress, &zero.FloatAddress, sizeof(evt.FloatAddress)))
        << "FillDelPeerEvent left poisoned bytes in FloatAddress -- this is "
           "kernel pool leaked to user mode in OvpnDeviceNotifyPeerDel.";

    /* Catch padding-byte leaks (the 4-byte hole at offset 12 on x64). Compare
     * the full struct against an authoritative zero+fields buffer. */
    OVPN_NOTIFY_EVENT expected;
    std::memset(&expected, 0, sizeof(expected));
    expected.Cmd = OVPN_CMD_DEL_PEER;
    expected.PeerId = 42;
    expected.DelPeerReason = OVPN_DEL_PEER_REASON_EXPIRED;
    ASSERT_EQ(0, std::memcmp(&evt, &expected, sizeof(evt)))
        << "FillDelPeerEvent left uninitialised padding bytes in the struct.";
}

TEST(NotifyEventFill, FloatPeerLeavesNoPoolResidue)
{
    OVPN_NOTIFY_EVENT evt = MakePoisonedEvent();

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1194);
    addr.sin_addr.s_addr = htonl(0x01020304);

    NotifyQueue::FillFloatPeerEvent(&evt, 7, reinterpret_cast<PSOCKADDR>(&addr));

    ASSERT_EQ(evt.Cmd, OVPN_CMD_FLOAT_PEER);
    ASSERT_EQ(evt.PeerId, 7);

    /* sockaddr_in occupies the first 16 bytes of sockaddr_storage; the
     * remaining 112 bytes must be zero, not pool residue. */
    auto* bytes = reinterpret_cast<const uint8_t*>(&evt.FloatAddress);
    for (size_t i = sizeof(struct sockaddr_in); i < sizeof(evt.FloatAddress); ++i) {
        ASSERT_EQ(bytes[i], 0u)
            << "FillFloatPeerEvent left poison byte 0x" << std::hex << (int)bytes[i]
            << " at FloatAddress[" << std::dec << i << "] -- pool leak.";
    }

    /* DelPeerReason is irrelevant for FLOAT_PEER and must be zero (not the
     * 0xABABABAB poison pattern), to match the explicit RtlZeroMemory in the
     * helper. */
    OVPN_DEL_PEER_REASON zeroReason;
    std::memset(&zeroReason, 0, sizeof(zeroReason));
    ASSERT_EQ(0, std::memcmp(&evt.DelPeerReason, &zeroReason, sizeof(zeroReason)));
}

/* OVPN_PEER_STATS has a 4-byte alignment hole between PeerId (offset 0) and
 * LinkRxBytes (offset 8). OvpnFillPeerStats writes into an un-zeroed
 * METHOD_BUFFERED system buffer, so that hole must be zeroed or it leaks
 * non-paged pool to user mode. Poison first; only field-controlled bytes and
 * zeros may survive. */
TEST(PeerStatsFill, LeavesNoPoolResidue)
{
    OVPN_PEER_STATS s;
    std::memset(&s, 0xAB, sizeof(s));

    OvpnFillPeerStats(&s, 5, 100, 200, 300, 400);

    ASSERT_EQ(s.PeerId, 5);
    ASSERT_EQ(s.LinkRxBytes, 100);
    ASSERT_EQ(s.LinkTxBytes, 200);
    ASSERT_EQ(s.VpnRxBytes, 300);
    ASSERT_EQ(s.VpnTxBytes, 400);

    /* Compare the whole struct against an authoritative zero+fields buffer to
     * catch the alignment-hole leak (and any other uninitialised padding). */
    OVPN_PEER_STATS expected;
    std::memset(&expected, 0, sizeof(expected));
    expected.PeerId = 5;
    expected.LinkRxBytes = 100;
    expected.LinkTxBytes = 200;
    expected.VpnRxBytes = 300;
    expected.VpnTxBytes = 400;
    ASSERT_EQ(0, std::memcmp(&s, &expected, sizeof(s)))
        << "OvpnFillPeerStats left uninitialised padding (the 4-byte hole "
           "between PeerId and LinkRxBytes) -- kernel pool leaked to user mode "
           "in OvpnPeerGetStats.";
}
