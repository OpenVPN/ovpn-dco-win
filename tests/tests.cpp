#include <gtest/gtest.h>
#include <memory>

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

TEST_F(CryptoTest, EpochKeyGeneration) {
    // check that the keys look like expected
    ASSERT_EQ(keySlot.FutureEpochKeys[0].Epoch, 2);
    ASSERT_EQ(keySlot.FutureEpochKeys[15].Epoch, 17);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, 1);
    ASSERT_EQ(keySlot.EpochKeyRecv.Epoch, 17);

    // Now replace the recv key with the 6th future key (epoch = 8)
    BCryptDestroyKey(keySlot.Decrypt.Key);
    RtlZeroMemory(&keySlot.Decrypt, sizeof(keySlot.Decrypt));
    ASSERT_EQ(keySlot.FutureEpochKeys[6].Epoch, 8);
    keySlot.Decrypt = keySlot.FutureEpochKeys[6];
    RtlZeroMemory(&keySlot.FutureEpochKeys[6].Epoch, sizeof(OvpnCryptoKeyContext));

    OvpnCryptoEpochGenerateFutureRecvKeys(&keySlot, &opts);
    ASSERT_EQ(keySlot.FutureEpochKeys[0].Epoch, 9);
    ASSERT_EQ(keySlot.FutureEpochKeys[15].Epoch, 24);
}

TEST_F(CryptoTest, EpochKeyRotation) {
    /* should replace send + key recv */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 9, &opts);

    ASSERT_EQ(keySlot.Decrypt.Epoch, 9);
    ASSERT_EQ(keySlot.Encrypt.Epoch, 9);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, 9);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, 1);

    /* Iterate the data send key four times to get it to 13 */
    for (int i = 0; i < 4; i++)
    {
        OvpnCryptoEpochKeyIterate(&keySlot.EpochKeySend, opts.HkdfAlgHandle);

        BCryptDestroyKey(&keySlot.Encrypt.Key);
        RtlZeroMemory(&keySlot.Encrypt, sizeof(OvpnCryptoKeyContext));

        OvpnCryptoEpochInitKey(&keySlot.Encrypt, &keySlot.EpochKeySend, &opts);
    }
    ASSERT_EQ(keySlot.Encrypt.Epoch, 13);

    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 10, &opts);
    ASSERT_EQ(keySlot.Decrypt.Epoch, 10);
    ASSERT_EQ(keySlot.Encrypt.Epoch, 13);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, 13);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, 9);

    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 12, &opts);
    ASSERT_EQ(keySlot.Decrypt.Epoch, 12);
    ASSERT_EQ(keySlot.Encrypt.Epoch, 13);
    ASSERT_EQ(keySlot.EpochKeySend.Epoch, 13);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, 10);

    OvpnCryptoEpochKeyIterate(&keySlot.EpochKeySend, opts.HkdfAlgHandle);

    BCryptDestroyKey(&keySlot.Encrypt.Key);
    RtlZeroMemory(&keySlot.Encrypt, sizeof(OvpnCryptoKeyContext));

    OvpnCryptoEpochInitKey(&keySlot.Encrypt, &keySlot.EpochKeySend, &opts);

    ASSERT_EQ(keySlot.Encrypt.Epoch, 14);
}

TEST_F(CryptoTest, EpochKeyReceiveLookup)
{
    /* lookup some wacky things that should fail */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 2000), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, -1), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 0xefff), nullptr);

    /* Lookup the edges of the current window */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 0), nullptr);
    ASSERT_EQ(keySlot.RetiringEpochDataReceiveKey.Epoch, 0);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1)->Epoch, 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 2)->Epoch, 2);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 16)->Epoch, 16);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 17)->Epoch, 17);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 18), nullptr);

    /* Should move 1 to retiring key but leave 2-6 undefined, 7 as
     * active and 8-23 as future keys*/
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 7, &opts);

    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 0), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1)->Epoch, 1);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1), &keySlot.RetiringEpochDataReceiveKey);

    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 2), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 3), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 4), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 5), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 6), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 21)->Epoch, 21);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 22)->Epoch, 22);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 23)->Epoch, 23);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 24), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 25), nullptr);

    /* Should move 7 to retiring key and have 8 as active key and
     * 9-24 as future keys */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, 8, &opts);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 0), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 1), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 2), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 3), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 4), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 5), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 6), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 7)->Epoch, 7);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 7), &keySlot.RetiringEpochDataReceiveKey);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 8)->Epoch, 8);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 23)->Epoch, 23);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 24)->Epoch, 24);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 25), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, 26), nullptr);
}

TEST_F(CryptoTest, EpochKeyOverflow)
{
    /* Modify the receive epoch and keys to have a very high epoch to test
     * the end of array. Iterating through all 65k keys takes a 2-3s, so we
     * avoid this for the unit test */
    keySlot.Decrypt.Epoch = 65516;
    keySlot.Encrypt.Epoch = 65516;

    keySlot.EpochKeySend.Epoch = 65516;
    keySlot.EpochKeyRecv.Epoch = 65516 + FUTURE_EPOCH_KEYS_COUNT;

    for (int i = 0; i < FUTURE_EPOCH_KEYS_COUNT; ++i) {
        keySlot.FutureEpochKeys[i].Epoch = 65517 + i;
    }

    /* Move the last few keys until we are close to the limit */
    while (keySlot.Decrypt.Epoch < (UINT16_MAX - 24))
    {
        OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, keySlot.Decrypt.Epoch + 10, &opts);
    }

    /* Looking up this key should still work as it will not break the limit
     * when generating keys */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX - 18)->Epoch, UINT16_MAX - 18);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX - 17)->Epoch, UINT16_MAX - 17);

    /* This key is no longer eligible for decrypting as the 16 future keys
     * would be larger than uint16_t maximum */
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX - FUTURE_EPOCH_KEYS_COUNT), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX), nullptr);

    /* Check that moving to the last possible epoch works */
    OvpnCryptoEpochReplaceUpdateRecvKey(&keySlot, UINT16_MAX - 17, &opts);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX - 17)->Epoch, UINT16_MAX - 17);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX - 16), nullptr);
    ASSERT_EQ(OvpnCryptoEpochLookupDecryptKey(&keySlot, UINT16_MAX), nullptr);
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
