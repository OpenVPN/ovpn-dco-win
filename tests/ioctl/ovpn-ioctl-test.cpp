/*
 * ovpn-ioctl-test - drive the ovpn-dco ioctl surface directly.
 *
 * The stress rig reaches the driver through OpenVPN, so it only ever produces orderings
 * OpenVPN produces, at the rate a TLS handshake allows. This talks to the device itself:
 * malformed buffers, illegal orderings, and peer churn at memory speed rather than
 * handshake speed.
 *
 * The device is exclusive (WdfDeviceInitSetExclusive in Driver.cpp), so this owns it for
 * the duration and cannot run alongside OpenVPN.
 *
 * Run it with Driver Verifier armed. On its own it only reports what the driver returned;
 * the verdict comes from the machine still being alive and the driver unloading cleanly.
 */

#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>    // InetPtonA, for --peer
#include <windows.h>
// CTL_CODE and friends. Included explicitly rather than relying on windows.h, which
// leaves it out under WIN32_LEAN_AND_MEAN.
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>

#include "../../uapi/ovpn-dco.h"

// The data-channel header, copied rather than included: crypto.h is a kernel header and
// will not compile here. A packet starts with one big-endian word, the opcode in the top
// five bits of the first byte and the peer id in the low 24.
#define OVPN_OP_DATA_V2     9
#define OVPN_OPCODE_SHIFT   3
#define OVPN_KEY_ID_MASK    0x07
#define OVPN_PEER_ID_MASK   0x00FFFFFF

// Epoch data keys put a 64 bit packet id straight after the 4 byte header, with the
// epoch in its top 16 bits. The driver looks the epoch up and derives future keys
// before it verifies anything, so a packet that will never decrypt still drives the
// whole ratchet. The lookahead is bounded (FUTURE_EPOCH_KEYS_COUNT in crypto_epoch.h),
// and the arithmetic around that bound is what this aims at.
#define OVPN_DATA_V2_LEN        4
#define FUTURE_EPOCH_KEYS_COUNT 4
#define CRYPTO_OPTIONS_EPOCH    (1<<1)

// The control channel is ReadFile and WriteFile on the same handle. In MP mode a write
// is prefixed with the peer's sockaddr and Driver.cpp switches on sa_family to decide
// how far to skip it, and a read is handed the sockaddr the packet came from followed
// by the packet. OVPN_DCO_MTU_MAX is adapter.h's, the cap a write is refused past.
#define OVPN_DCO_MTU_MAX    1500
// what the driver will queue for a read: bufferpool.h's rx packet buffer
#define OVPN_SOCKET_RX_BUF  2048

#define DEVICE_PATH "\\\\.\\ovpn-dco"

struct IoctlDef {
    DWORD       code;
    const char* name;
    size_t      inSize;     // 0 when the ioctl takes no input
    size_t      outSize;    // 0 when it returns nothing
    bool        mpOnly;
    bool        p2pOnly;
    bool        blocking;   // may not complete until something else happens
};

// Sizes are what the driver retrieves with WdfRequestRetrieveInputBuffer, so a mutation
// that shortens the buffer should be refused rather than read past.
static const IoctlDef kIoctls[] = {
    { OVPN_IOCTL_NEW_PEER,      "NEW_PEER",      sizeof(OVPN_NEW_PEER),       0,                        false, true,  false },
    { OVPN_IOCTL_GET_STATS,     "GET_STATS",     0,                           sizeof(OVPN_STATS),       false, false, false },
    { OVPN_IOCTL_NEW_KEY,       "NEW_KEY",       sizeof(OVPN_CRYPTO_DATA),    0,                        false, false, false },
    { OVPN_IOCTL_SWAP_KEYS,     "SWAP_KEYS",     0,                           0,                        false, true,  false },
    { OVPN_IOCTL_SET_PEER,      "SET_PEER",      sizeof(OVPN_SET_PEER),       0,                        false, true,  false },
    { OVPN_IOCTL_START_VPN,     "START_VPN",     0,                           0,                        false, true,  false },
    { OVPN_IOCTL_DEL_PEER,      "DEL_PEER",      0,                           0,                        false, true,  false },
    { OVPN_IOCTL_GET_VERSION,   "GET_VERSION",   0,                           sizeof(OVPN_VERSION),     false, false, false },
    { OVPN_IOCTL_NEW_KEY_V2,    "NEW_KEY_V2",    sizeof(OVPN_CRYPTO_DATA_V2), 0,                        false, false, false },
    { OVPN_IOCTL_SET_MODE,      "SET_MODE",      sizeof(OVPN_SET_MODE),       0,                        false, false, false },
    { OVPN_IOCTL_MP_START_VPN,  "MP_START_VPN",  sizeof(OVPN_MP_START_VPN),   0,                        true,  false, false },
    { OVPN_IOCTL_MP_NEW_PEER,   "MP_NEW_PEER",   sizeof(OVPN_MP_NEW_PEER),    0,                        true,  false, false },
    { OVPN_IOCTL_MP_SET_PEER,   "MP_SET_PEER",   sizeof(OVPN_MP_SET_PEER),    0,                        true,  false, false },
    { OVPN_IOCTL_NOTIFY_EVENT,  "NOTIFY_EVENT",  0,                           sizeof(OVPN_NOTIFY_EVENT),false, false, true  },
    { OVPN_IOCTL_MP_DEL_PEER,   "MP_DEL_PEER",   sizeof(OVPN_MP_DEL_PEER),    0,                        true,  false, false },
    { OVPN_IOCTL_MP_SWAP_KEYS,  "MP_SWAP_KEYS",  sizeof(OVPN_MP_SWAP_KEYS),   0,                        true,  false, false },
    { OVPN_IOCTL_MP_ADD_IROUTE, "MP_ADD_IROUTE", sizeof(OVPN_MP_IROUTE),      0,                        true,  false, false },
    { OVPN_IOCTL_MP_DEL_IROUTE, "MP_DEL_IROUTE", sizeof(OVPN_MP_IROUTE),      0,                        true,  false, false },
    { OVPN_IOCTL_GET_PEER_STATS,"GET_PEER_STATS",sizeof(OVPN_GET_PEER_STATS), sizeof(OVPN_PEER_STATS),  true,  false, false },
};

static const size_t kIoctlCount = sizeof(kIoctls) / sizeof(kIoctls[0]);

static unsigned g_seed = 0;

static unsigned rnd()
{
    // xorshift32: small, and reproducible from the seed the run prints
    g_seed ^= g_seed << 13;
    g_seed ^= g_seed >> 17;
    g_seed ^= g_seed << 5;
    return g_seed;
}

static HANDLE open_device()
{
    // Overlapped, so every call can be given a deadline: an ioctl that parks (NOTIFY_EVENT
    // does by design) would otherwise stall the sweep, and one that parks unexpectedly is
    // itself worth reporting rather than hanging on.
    HANDLE h = CreateFileA(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        fprintf(stderr, "cannot open %s: error %lu%s\n", DEVICE_PATH, err,
                err == ERROR_ACCESS_DENIED ? " (run as administrator)" :
                err == ERROR_SHARING_VIOLATION ? " (the device is exclusive; stop openvpn)" : "");
    }
    return h;
}

// A call that pended past its deadline. Reported rather than waited on, and cancelled so
// the sweep can carry on; cancelling a pended request also exercises the driver's own
// cancel path, which is where lost-wakeup bugs live.
#define CALL_PENDED 0xFFFFFFFF

// Counted per control code, not in total: NOTIFY_EVENT parking is by design, anything
// else pending for two seconds is a finding, and one number cannot tell them apart.
static LONG g_pended[64];

static int pended_slot(DWORD code) { return (int)((code >> 2) & 63); }

// One ioctl with an arbitrary buffer. Never asserts on the status: a refusal is the
// correct answer to most of what this sends, and the driver is free to choose which.
static DWORD call(HANDLE h, DWORD code, void* in, DWORD inLen, void* out, DWORD outLen)
{
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent)
        return GetLastError();

    DWORD returned = 0, err = 0;
    if (DeviceIoControl(h, code, in, inLen, out, outLen, &returned, &ov)) {
        CloseHandle(ov.hEvent);
        return 0;
    }

    err = GetLastError();
    if (err != ERROR_IO_PENDING) {
        CloseHandle(ov.hEvent);
        return err;
    }

    if (WaitForSingleObject(ov.hEvent, 2000) == WAIT_OBJECT_0) {
        err = GetOverlappedResult(h, &ov, &returned, FALSE) ? 0 : GetLastError();
    } else {
        CancelIoEx(h, &ov);
        GetOverlappedResult(h, &ov, &returned, TRUE);
        InterlockedIncrement(&g_pended[pended_slot(code)]);
        err = CALL_PENDED;
    }
    CloseHandle(ov.hEvent);
    return err;
}

struct Counters {
    unsigned calls;
    unsigned refused;
    unsigned accepted;
    unsigned pended;
};

// Buffer shapes, which is where this driver's input-validation bugs have actually been:
// a short input buffer read past its end, and an output buffer whose padding went back
// to userspace. Anything other than a refusal for a truncated input is worth a look.
static void mutate_sizes(HANDLE h, const IoctlDef& def, Counters& c)
{
    std::vector<unsigned char> in(def.inSize ? def.inSize * 2 : 64, 0);
    std::vector<unsigned char> out(def.outSize ? def.outSize * 2 : 64, 0);

    std::vector<DWORD> inLens;
    inLens.push_back(0);
    if (def.inSize > 0) {
        inLens.push_back(1);
        if (def.inSize > 2)
            inLens.push_back((DWORD)(def.inSize - 1));
        inLens.push_back((DWORD)def.inSize);
        inLens.push_back((DWORD)(def.inSize + 1));
        inLens.push_back((DWORD)(def.inSize * 2));
    }

    std::vector<DWORD> outLens;
    outLens.push_back(0);
    if (def.outSize > 0) {
        outLens.push_back(1);
        if (def.outSize > 2)
            outLens.push_back((DWORD)(def.outSize - 1));
        outLens.push_back((DWORD)def.outSize);
        outLens.push_back((DWORD)(def.outSize * 2));
    }

    for (size_t i = 0; i < inLens.size(); i++) {
        for (size_t j = 0; j < outLens.size(); j++) {
            // A blocking ioctl with a legal buffer parks until something wakes it, which
            // would stall the sweep; only its malformed shapes are interesting here.
            if (def.blocking && outLens[j] >= def.outSize)
                continue;

            // fill with noise so a read past the end has something recognisable in it
            for (size_t k = 0; k < in.size(); k++)
                in[k] = (unsigned char)rnd();

            DWORD err = call(h, def.code, inLens[i] ? in.data() : NULL, inLens[i],
                             outLens[j] ? out.data() : NULL, outLens[j]);
            c.calls++;
            if (err == CALL_PENDED)
                c.pended++;
            else if (err)
                c.refused++;
            else {
                c.accepted++;
                // Accepting a buffer shorter than the struct the driver reads is the
                // shape of a read past the end, so name it rather than counting it.
                if (def.inSize && inLens[i] < def.inSize)
                    printf("  ! %s accepted a %lu-byte input, struct is %zu\n",
                           def.name, inLens[i], def.inSize);
                if (def.outSize && outLens[j] < def.outSize && outLens[j] != 0)
                    printf("  ! %s accepted a %lu-byte output, struct is %zu\n",
                           def.name, outLens[j], def.outSize);
            }
        }
    }
}

// NULL pointers with a non-zero length, which the IO manager should catch before the
// driver sees them, and a length that would overflow a size calculation.
static void mutate_pointers(HANDLE h, const IoctlDef& def, Counters& c)
{
    unsigned char scratch[256] = { 0 };

    DWORD err = call(h, def.code, NULL, (DWORD)(def.inSize ? def.inSize : 16), NULL, 0);
    c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;

    err = call(h, def.code, scratch, sizeof(scratch), NULL, 0xFFFFFFF0);
    c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;

    err = call(h, def.code, scratch, 0xFFFFFFF0, scratch, sizeof(scratch));
    c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;
}

// Well-formed buffers carrying values outside what the driver should accept. These are
// the ones where a refusal is a judgement call rather than obvious, so the run reports
// what happened instead of deciding.
static void mutate_values(HANDLE h, const IoctlDef& def, Counters& c)
{
    if (def.code == OVPN_IOCTL_SET_MODE) {
        for (int m = -1; m <= 3; m++) {
            OVPN_SET_MODE sm;
            sm.Mode = (OVPN_MODE)m;
            DWORD err = call(h, def.code, &sm, sizeof(sm), NULL, 0);
            c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;
            if (!err && (m < 0 || m > 1))
                printf("  ! SET_MODE accepted mode %d\n", m);
        }
        return;
    }

    if (def.code == OVPN_IOCTL_MP_DEL_PEER || def.code == OVPN_IOCTL_MP_SWAP_KEYS) {
        const int ids[] = { -1, 0, 1, 0x7FFFFFFF, (int)0x80000000 };
        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            OVPN_MP_DEL_PEER d;
            d.PeerId = ids[i];
            DWORD err = call(h, def.code, &d, sizeof(d), NULL, 0);
            c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;
        }
        return;
    }

    if (def.code == OVPN_IOCTL_MP_ADD_IROUTE || def.code == OVPN_IOCTL_MP_DEL_IROUTE) {
        const int netbits[] = { -1, 0, 24, 32, 33, 128, 129, 0x7FFFFFFF };
        for (size_t i = 0; i < sizeof(netbits) / sizeof(netbits[0]); i++) {
            for (int v6 = 0; v6 <= 1; v6++) {
                OVPN_MP_IROUTE r;
                memset(&r, 0, sizeof(r));
                r.Netbits = netbits[i];
                r.IPv6 = v6;
                r.PeerId = (int)(rnd() % 64);
                DWORD err = call(h, def.code, &r, sizeof(r), NULL, 0);
                c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;
                int max = v6 ? 128 : 32;
                if (!err && (netbits[i] < 0 || netbits[i] > max))
                    printf("  ! %s accepted netbits %d for IPv%d\n",
                           def.name, netbits[i], v6 ? 6 : 4);
            }
        }
        return;
    }

    if (def.code == OVPN_IOCTL_NEW_KEY_V2) {
        const unsigned char keyLens[] = { 0, 1, 15, 16, 17, 24, 31, 32, 33, 255 };
        for (size_t i = 0; i < sizeof(keyLens) / sizeof(keyLens[0]); i++) {
            OVPN_CRYPTO_DATA_V2 k;
            memset(&k, 0, sizeof(k));
            k.V1.Encrypt.KeyLen = keyLens[i];
            k.V1.Decrypt.KeyLen = keyLens[i];
            k.V1.CipherAlg = OVPN_CIPHER_ALG_AES_GCM;
            k.V1.KeySlot = OVPN_KEY_SLOT_PRIMARY;
            k.V1.PeerId = (int)(rnd() % 64);
            DWORD err = call(h, def.code, &k, sizeof(k), NULL, 0);
            c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;
            if (!err && keyLens[i] != 16 && keyLens[i] != 24 && keyLens[i] != 32)
                printf("  ! NEW_KEY_V2 accepted KeyLen %u\n", keyLens[i]);
        }
        // cipher algorithms past the end of the enum
        for (int alg = -1; alg <= 4; alg++) {
            OVPN_CRYPTO_DATA_V2 k;
            memset(&k, 0, sizeof(k));
            k.V1.Encrypt.KeyLen = 32;
            k.V1.Decrypt.KeyLen = 32;
            k.V1.CipherAlg = (OVPN_CIPHER_ALG)alg;
            DWORD err = call(h, def.code, &k, sizeof(k), NULL, 0);
            c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;
        }
        return;
    }

    // Anything with a sockaddr in it: the family field decides how far the driver reads.
    if (def.code == OVPN_IOCTL_MP_NEW_PEER || def.code == OVPN_IOCTL_NEW_PEER ||
        def.code == OVPN_IOCTL_MP_START_VPN) {
        const unsigned short families[] = { 0, AF_INET, AF_INET6, AF_UNIX, 0xFFFF, 1234 };
        for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
            unsigned char buf[512];
            memset(buf, 0, sizeof(buf));
            // both the local and the remote sockaddr start at a known offset
            *(unsigned short*)buf = families[i];
            *(unsigned short*)(buf + sizeof(SOCKADDR_IN6)) = families[i];
            DWORD err = call(h, def.code, buf, (DWORD)def.inSize, NULL, 0);
            c.calls++; if (err == CALL_PENDED) c.pended++; else if (err) c.refused++; else c.accepted++;
        }
    }
}

/* ---------------------------------------------------------------------------
 * churn: several threads on the one handle, because the bugs this driver has
 * actually had were lifecycle races rather than bad input. A peer is created and
 * destroyed while another thread installs keys for it, a third moves its routes,
 * a fourth reads its stats, and datagrams for it keep arriving throughout.
 * ------------------------------------------------------------------------- */

static volatile LONG g_stop = 0;
static LONG g_ops[12];
// Counted so a run can show a path was reached rather than assumed: no expiries means
// the timer never freed a peer, and no epoch keys means the crafted packet ids drove
// nothing.
static LONG g_expired;
static LONG g_ctrlRead;
static LONG g_ctrlWritten;
static LONG g_epochKeysTaken;
static LONG g_epochKeysRefused;

#define PEER_SPACE 64           // small, so ids are reused constantly
// The top of the id space is left to the driver: those peers get a short keepalive and
// are never deleted by hand, so the timer expires them and the free runs from the timer
// rather than from an ioctl. That is a different path, and it has had a use after free.
#define EXPIRY_LANE_FIRST 48

struct ThreadArg {
    HANDLE   h;
    unsigned seed;
    int      slot;
    USHORT   port;
};

static unsigned trnd(unsigned* seed)
{
    unsigned x = *seed;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *seed = x ? x : 1;
    return *seed;
}

static void fill_sockaddr(SOCKADDR_IN* sa, ULONG addr, USHORT port)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = htonl(addr);
}

// ReadFile and WriteFile on the device, with the same deadline the ioctls get. A read
// parks until a control packet arrives, so a timeout here is the design rather than a
// finding — but the cancel that follows is a path of its own, and it runs against the
// lock the receive side takes to hand a packet to a parked reader.
static DWORD rw_dev(HANDLE h, void* buf, DWORD len, bool write, DWORD* got)
{
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent)
        return GetLastError();

    DWORD done = 0, err = 0;
    BOOL ok = write ? WriteFile(h, buf, len, &done, &ov) : ReadFile(h, buf, len, &done, &ov);
    if (!ok) {
        err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, 2000) == WAIT_OBJECT_0) {
                err = GetOverlappedResult(h, &ov, &done, FALSE) ? 0 : GetLastError();
            } else {
                CancelIoEx(h, &ov);
                GetOverlappedResult(h, &ov, &done, TRUE);
                err = CALL_PENDED;
            }
        }
    }
    if (got)
        *got = done;
    CloseHandle(ov.hEvent);
    return err;
}

static DWORD WINAPI thread_peers(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    while (!g_stop) {
        int id = (int)(trnd(&a->seed) % PEER_SPACE);
        bool expiryLane = id >= EXPIRY_LANE_FIRST;
        if (expiryLane || (trnd(&a->seed) & 1)) {
            OVPN_MP_NEW_PEER np;
            memset(&np, 0, sizeof(np));
            fill_sockaddr((SOCKADDR_IN*)&np.Local, INADDR_ANY, a->port);
            fill_sockaddr((SOCKADDR_IN*)&np.Remote, 0x0A000001 + id, (USHORT)(40000 + id));
            np.VpnAddr4.S_un.S_addr = htonl(0x0A580000 + id);
            np.PeerId = id;
            DWORD err = call(a->h, OVPN_IOCTL_MP_NEW_PEER, &np, sizeof(np), NULL, 0);
            // Only on a peer that is actually new: MP_SET_PEER restarts the receive
            // timer, so re-arming an existing lane peer every pass would keep it alive
            // for the whole run and nothing would ever expire.
            if (expiryLane && err == 0) {
                OVPN_MP_SET_PEER sp;
                sp.PeerId = id;
                sp.KeepaliveInterval = 1;
                sp.KeepaliveTimeout = 2;
                sp.MSS = 0;
                call(a->h, OVPN_IOCTL_MP_SET_PEER, &sp, sizeof(sp), NULL, 0);
            }
        } else {
            OVPN_MP_DEL_PEER dp;
            dp.PeerId = id;
            call(a->h, OVPN_IOCTL_MP_DEL_PEER, &dp, sizeof(dp), NULL, 0);
        }
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

static DWORD WINAPI thread_keys(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    while (!g_stop) {
        int id = (int)(trnd(&a->seed) % PEER_SPACE);
        if (trnd(&a->seed) & 1) {
            OVPN_CRYPTO_DATA_V2 k;
            memset(&k, 0, sizeof(k));
            k.V1.PeerId = id;
            k.V1.CipherAlg = OVPN_CIPHER_ALG_AES_GCM;
            k.V1.KeySlot = (trnd(&a->seed) & 1) ? OVPN_KEY_SLOT_SECONDARY : OVPN_KEY_SLOT_PRIMARY;
            // Half of them epoch keys, so both the ratchet and the plain packet id path
            // are live at once and a peer id can be reused across the two.
            bool epochKey = (trnd(&a->seed) & 1) != 0;
            if (epochKey)
                k.CryptoOptions |= CRYPTO_OPTIONS_EPOCH;
            k.V1.KeyId = (UCHAR)(trnd(&a->seed) & 7);
            k.V1.Encrypt.KeyLen = 32;
            k.V1.Decrypt.KeyLen = 32;
            for (int i = 0; i < 32; i++) {
                k.V1.Encrypt.Key[i] = (unsigned char)trnd(&a->seed);
                k.V1.Decrypt.Key[i] = (unsigned char)trnd(&a->seed);
            }
            DWORD kerr = call(a->h, OVPN_IOCTL_NEW_KEY_V2, &k, sizeof(k), NULL, 0);
            if (epochKey)
                InterlockedIncrement(kerr ? &g_epochKeysRefused : &g_epochKeysTaken);
        } else {
            OVPN_MP_SWAP_KEYS sk;
            sk.PeerId = id;
            call(a->h, OVPN_IOCTL_MP_SWAP_KEYS, &sk, sizeof(sk), NULL, 0);
        }
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

static DWORD WINAPI thread_routes(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    while (!g_stop) {
        OVPN_MP_IROUTE r;
        memset(&r, 0, sizeof(r));
        r.PeerId = (int)(trnd(&a->seed) % PEER_SPACE);
        // deliberately overlapping prefixes, so ownership keeps moving between peers
        r.Netbits = (int)(16 + trnd(&a->seed) % 17);
        r.Addr.Addr4.S_un.S_addr = htonl(0x0A5A0000 | (trnd(&a->seed) & 0xFFFF));
        call(a->h, (trnd(&a->seed) & 1) ? OVPN_IOCTL_MP_ADD_IROUTE : OVPN_IOCTL_MP_DEL_IROUTE,
             &r, sizeof(r), NULL, 0);
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

static DWORD WINAPI thread_stats(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    OVPN_STATS st;
    OVPN_PEER_STATS ps;
    while (!g_stop) {
        unsigned pick = trnd(&a->seed) % 3;
        if (pick == 0) {
            call(a->h, OVPN_IOCTL_GET_STATS, NULL, 0, &st, sizeof(st));
        } else if (pick == 1) {
            OVPN_GET_PEER_STATS gs;
            gs.PeerId = (int)(trnd(&a->seed) % PEER_SPACE);
            call(a->h, OVPN_IOCTL_GET_PEER_STATS, &gs, sizeof(gs), &ps, sizeof(ps));
        } else {
            OVPN_MP_SET_PEER sp;
            // not the expiry lane: a random timeout of up to two minutes would re-arm
            // those peers past the end of the run
            sp.PeerId = (int)(trnd(&a->seed) % EXPIRY_LANE_FIRST);
            sp.KeepaliveInterval = (LONG)(trnd(&a->seed) % 30);
            sp.KeepaliveTimeout = (LONG)(trnd(&a->seed) % 120);
            sp.MSS = (LONG)(1000 + trnd(&a->seed) % 400);
            call(a->h, OVPN_IOCTL_MP_SET_PEER, &sp, sizeof(sp), NULL, 0);
        }
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

// The notify queue is its own surface: a reader parked on it while peers are deleted
// under it is what a userspace server does, and the control path has had a lost wakeup
// before. Every call carries the usual deadline, so a missed wakeup shows as a timeout
// rather than as a hang.
static DWORD WINAPI thread_notify(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    OVPN_NOTIFY_EVENT ev;
    while (!g_stop) {
        if (call(a->h, OVPN_IOCTL_NOTIFY_EVENT, NULL, 0, &ev, sizeof(ev)) == 0 &&
            ev.Cmd == OVPN_CMD_DEL_PEER && ev.DelPeerReason == OVPN_DEL_PEER_REASON_EXPIRED)
            InterlockedIncrement(&g_expired);
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

// Control-channel writes. The sockaddr prefix is what this aims at: a buffer holding
// sa_family and nothing else, one exactly the length of the prefix so no payload is
// left, an AF_INET6 family over an AF_INET-sized buffer, families the switch does not
// know, and payloads either side of the MTU cap. The driver decides how far to read
// from the family the caller supplied, which is the shape of a past finding here.
static DWORD WINAPI thread_ctrl_tx(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    unsigned char buf[sizeof(SOCKADDR_IN6) + OVPN_DCO_MTU_MAX + 64];
    const DWORD hdr = (DWORD)sizeof(SOCKADDR_IN);

    while (!g_stop) {
        SOCKADDR_IN sa;
        // loopback discard, so a write the driver accepts leaves the machine alone and
        // does not arrive back at its own listen port
        fill_sockaddr(&sa, 0x7F000001, (USHORT)9);
        memcpy(buf, &sa, sizeof(sa));
        for (size_t i = hdr; i < sizeof(buf); i++)
            buf[i] = (unsigned char)trnd(&a->seed);

        DWORD len;
        switch (trnd(&a->seed) % 8) {
        case 0: len = sizeof(USHORT); break;                  // sa_family, nothing else
        case 1: len = hdr; break;                             // the prefix and no payload
        case 2: len = hdr - 1; break;                         // one short of the prefix
        case 3:                                               // v6 family over a v4 buffer
            ((SOCKADDR*)buf)->sa_family = AF_INET6;
            len = hdr + 8;
            break;
        case 4:                                               // a family the switch refuses
            ((SOCKADDR*)buf)->sa_family = (USHORT)trnd(&a->seed);
            len = hdr + 16;
            break;
        case 5: len = hdr + OVPN_DCO_MTU_MAX; break;          // at the cap
        case 6: len = hdr + OVPN_DCO_MTU_MAX + 1; break;      // past it
        default: len = hdr + 1 + (DWORD)(trnd(&a->seed) % 512); break;
        }

        if (rw_dev(a->h, buf, len, true, NULL) == 0)
            InterlockedIncrement(&g_ctrlWritten);
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

// Control-channel reads, which is where the lost wakeup lived: the read parks itself on
// PendingReadsQueue and then re-checks the queue under ControlRxLock, while the receive
// side takes the same lock to either hand the packet to a parked reader or queue it.
// Both sides run continuously here, since the traffic thread sends control packets too.
static DWORD WINAPI thread_ctrl_rx(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    unsigned char buf[OVPN_SOCKET_RX_BUF];

    while (!g_stop) {
        // now and then a buffer too small for what is queued, which the driver has to
        // refuse without losing either the packet or the request
        DWORD want = (trnd(&a->seed) % 8 == 0)
            ? (DWORD)(1 + trnd(&a->seed) % 16) : (DWORD)sizeof(buf);
        DWORD got = 0;
        if (rw_dev(a->h, buf, want, false, &got) == 0)
            InterlockedIncrement(&g_ctrlRead);
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

// Datagrams that will never decrypt, which is the point: they still drive the receive
// path, the peer lookup and the loss counters while peers are being freed underneath.
// No handshake, no crypto and no far end needed.
static DWORD WINAPI thread_traffic(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return 0;

    SOCKADDR_IN to;
    fill_sockaddr(&to, 0x7F000001, a->port);

    unsigned char pkt[256];
    while (!g_stop) {
        UINT32 peerId = trnd(&a->seed) % PEER_SPACE;
        // The driver calls anything that is not DATA_V2 a control packet. Rarely, so the
        // control queue stays near empty and the reader actually parks — which is the
        // race worth having. A flood instead just queues buffers: nothing reads them
        // faster than they arrive, and the pool grows to MAX_POOL_SIZE (bufferpool.cpp).
        static const UCHAR kControlOps[] = { 1, 2, 3, 4, 5, 7, 8, 10 };
        UCHAR op;
        if (trnd(&a->seed) % 256 == 0)
            op = (UCHAR)(kControlOps[trnd(&a->seed) % 8] << OVPN_OPCODE_SHIFT);
        else
            op = (UCHAR)((OVPN_OP_DATA_V2 << OVPN_OPCODE_SHIFT) | (trnd(&a->seed) & OVPN_KEY_ID_MASK));
        UINT32 hdr = ((UINT32)op << 24) | (peerId & OVPN_PEER_ID_MASK);
        pkt[0] = (unsigned char)(hdr >> 24);
        pkt[1] = (unsigned char)(hdr >> 16);
        pkt[2] = (unsigned char)(hdr >> 8);
        pkt[3] = (unsigned char)hdr;
        for (size_t i = 4; i < sizeof(pkt); i++)
            pkt[i] = (unsigned char)trnd(&a->seed);

        // A packet id whose epoch lands on, around and far past the lookahead: the
        // current key, the retiring one, each of the future keys, the first epoch
        // beyond them, and the ends of the range where the bound is computed.
        UINT16 epoch;
        switch (trnd(&a->seed) % 8) {
        case 0:  epoch = 0; break;                                      // refused outright
        case 1:  epoch = 0xFFFF; break;                                 // top of the range
        case 2:  epoch = (UINT16)(0xFFFF - (trnd(&a->seed) % 8)); break; // just under it
        default: epoch = (UINT16)(1 + trnd(&a->seed) % (FUTURE_EPOCH_KEYS_COUNT * 3));
        }
        UINT64 pid = ((UINT64)epoch << 48) | (trnd(&a->seed) & 0xFFFFFFFF);
        for (int b = 0; b < 8; b++)
            pkt[OVPN_DATA_V2_LEN + b] = (unsigned char)(pid >> (56 - 8 * b));
        int len = 4 + (int)(trnd(&a->seed) % (sizeof(pkt) - 4));
        sendto(s, (const char*)pkt, len, 0, (SOCKADDR*)&to, sizeof(to));
        InterlockedIncrement(&g_ops[a->slot]);
    }
    closesocket(s);
    return 0;
}

// Packets sent *into* the tunnel, which is the other half of the data path and the one
// the ioctls alone never reach. OvpnEvtTxQueueAdvance looks the destination up with
// OvpnFindPeerVPN4 and then, failing that, in the route trie (txqueue.cpp) — and that
// lookup runs while the routes thread is moving prefixes between peers underneath it.
//
// The encrypt afterwards fails, because these peers hold no usable key. That is fine:
// the lookup is the part worth stressing.
static bool configure_adapter(void)
{
    // Done with PowerShell rather than the IP Helper API: three lines here against a
    // page of GetAdaptersAddresses, for something that runs once per run.
    int rc = system("powershell -NoProfile -Command \""
        "$i = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Data Channel Offload*' } |"
        " Select-Object -First 1;"
        "if (-not $i) { exit 1 };"
        "Remove-NetIPAddress -InterfaceIndex $i.ifIndex -Confirm:$false -ErrorAction SilentlyContinue;"
        "New-NetIPAddress -InterfaceIndex $i.ifIndex -IPAddress 10.88.0.1 -PrefixLength 24"
        " -ErrorAction SilentlyContinue | Out-Null;"
        "New-NetRoute -InterfaceIndex $i.ifIndex -DestinationPrefix 10.90.0.0/16"
        " -NextHop 0.0.0.0 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null;"
        "exit 0\" >NUL 2>&1");
    return rc == 0;
}

static DWORD WINAPI thread_tx(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return 0;

    unsigned char payload[512];
    memset(payload, 0x5A, sizeof(payload));

    while (!g_stop) {
        SOCKADDR_IN to;
        if (trnd(&a->seed) & 1) {
            // a peer's own VPN address, so the peer table is consulted
            fill_sockaddr(&to, 0x0A580000 + (trnd(&a->seed) % PEER_SPACE), 9999);
        } else {
            // somewhere in the iroute range, so the route trie is consulted instead
            fill_sockaddr(&to, 0x0A5A0000 | (trnd(&a->seed) & 0xFFFF), 9999);
        }
        int len = 1 + (int)(trnd(&a->seed) % (sizeof(payload) - 1));
        sendto(s, (const char*)payload, len, 0, (SOCKADDR*)&to, sizeof(to));
        InterlockedIncrement(&g_ops[a->slot]);
    }
    closesocket(s);
    return 0;
}

// A deliberate repro for the deadlock this rig found. OvpnEvtIoWrite holds
// device->SpinLock *shared* across OvpnSocketSend (Driver.cpp:238 to :345). A write
// addressed to one of the machine's own addresses on the driver's own port is
// delivered by tcpip inline, on the sending thread, so the driver re-enters its own
// receive path and OvpnFindPeer asks for the same lock shared again. That nested
// acquire is safe on its own, but EX_SPIN_LOCK prefers writers: with a peer add or
// delete waiting for the lock exclusive, the second shared acquire queues behind it,
// the writer waits for the first one to be released, and neither ever moves.
//
// So it needs both halves, which is why the peers thread runs alongside. On a driver
// that still holds the lock across the send, this wedges the machine: several cores
// spinning at DISPATCH, no bugcheck, no recovery. It is kept out of the CI modes for
// that reason and has to be asked for by name.
static int run_selfsend(HANDLE h, int seconds, USHORT port, bool churn, bool control)
{
    OVPN_SET_MODE sm;
    sm.Mode = OVPN_MODE_MP;
    if (call(h, OVPN_IOCTL_SET_MODE, &sm, sizeof(sm), NULL, 0)) {
        fprintf(stderr, "SET_MODE(MP) refused; is something else holding the device?\n");
        return 1;
    }

    OVPN_MP_START_VPN sv, svOut;
    memset(&sv, 0, sizeof(sv));
    fill_sockaddr((SOCKADDR_IN*)&sv.ListenAddress, INADDR_ANY, port);
    DWORD err = call(h, OVPN_IOCTL_MP_START_VPN, &sv, sizeof(sv), &svOut, sizeof(svOut));
    if (err) {
        fprintf(stderr, "MP_START_VPN on port %u refused: error %lu\n", port, err);
        return 1;
    }

    printf("== writing to the driver's own listen port (127.0.0.1:%u) while peers churn\n", port);
    printf("   an unfixed driver deadlocks here: the machine stops answering and stays that\n"
           "   way, with no bugcheck. That is the finding, not anything printed below.\n");
    fflush(stdout);

    // The other half of the cycle: somebody asking for the lock exclusive. Without it
    // the nested shared acquire simply succeeds, which is what --no-churn demonstrates
    // and why this is a race rather than a hang every time.
    ThreadArg pressure;
    pressure.h = h;
    pressure.seed = g_seed ? g_seed : 1;
    pressure.slot = 0;
    pressure.port = port;
    HANDLE peersThread = churn ? CreateThread(NULL, 0, thread_peers, &pressure, 0, NULL) : NULL;
    // With a control opcode the packet comes back through the control receive path and
    // completes a parked read. Completing a request can make the framework dispatch the
    // next one to us, and if that one takes the lock exclusive while this thread still
    // holds it shared, the deadlock needs no second thread at all.
    ThreadArg reader;
    reader.h = h;
    reader.seed = (g_seed ? g_seed : 1) * 2654435761u;
    reader.slot = 1;
    reader.port = port;
    HANDLE readerThread = control ? CreateThread(NULL, 0, thread_ctrl_rx, &reader, 0, NULL) : NULL;
    if (!churn)
        puts("   --no-churn: nothing takes the lock exclusive, so this should survive");

    SOCKADDR_IN self;
    fill_sockaddr(&self, 0x7F000001, port);

    unsigned char msg[sizeof(SOCKADDR_IN) + 64];
    memcpy(msg, &self, sizeof(self));
    // DATA_V2, not a control opcode: only the data path looks a peer up, and that
    // lookup is what takes device->SpinLock shared a second time. A control packet
    // comes back in through OvpnSocketControlPacketReceived, which takes ControlRxLock
    // and nothing else, so it re-enters harmlessly.
    unsigned char* pkt = msg + sizeof(self);
    memset(pkt, 0x42, sizeof(msg) - sizeof(self));

    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)seconds * 1000;
    LONG writes = 0;
    while (GetTickCount64() < deadline) {
        UINT32 peerId = (UINT32)(writes % PEER_SPACE);
        // control opcode goes to OvpnSocketControlPacketReceived, data to the peer lookup
        UCHAR op = control ? (UCHAR)(7 << OVPN_OPCODE_SHIFT)
                           : (UCHAR)(OVPN_OP_DATA_V2 << OVPN_OPCODE_SHIFT);
        UINT32 hdr = ((UINT32)op << 24) | peerId;
        pkt[0] = (unsigned char)(hdr >> 24);
        pkt[1] = (unsigned char)(hdr >> 16);
        pkt[2] = (unsigned char)(hdr >> 8);
        pkt[3] = (unsigned char)hdr;
        rw_dev(h, msg, (DWORD)sizeof(msg), true, NULL);
        if (++writes % 1000 == 0) {
            printf("  %ld writes, still alive\n", writes);
            fflush(stdout);
        }
    }

    InterlockedExchange(&g_stop, 1);
    if (peersThread != NULL) {
        WaitForSingleObject(peersThread, 30000);
        CloseHandle(peersThread);
    }
    if (readerThread != NULL) {
        WaitForSingleObject(readerThread, 30000);
        CloseHandle(readerThread);
    }

    printf("== %ld writes, no deadlock\n", writes);
    for (int id = 0; id < PEER_SPACE; id++) {
        OVPN_MP_DEL_PEER dp;
        dp.PeerId = id;
        call(h, OVPN_IOCTL_MP_DEL_PEER, &dp, sizeof(dp), NULL, 0);
    }
    return 0;
}

// Binds the transport socket and reports what the driver saw, so a packet sent from
// somewhere else can be checked for arrival. Used to ask whether Windows delivers a
// datagram whose source address belongs to the receiving machine: if tcpip drops it
// before WSK, no counter moves.
static int run_listen(HANDLE h, int seconds, USHORT port)
{
    OVPN_SET_MODE sm;
    sm.Mode = OVPN_MODE_MP;
    if (call(h, OVPN_IOCTL_SET_MODE, &sm, sizeof(sm), NULL, 0)) {
        fprintf(stderr, "SET_MODE(MP) refused\n");
        return 1;
    }
    OVPN_MP_START_VPN sv, svOut;
    memset(&sv, 0, sizeof(sv));
    fill_sockaddr((SOCKADDR_IN*)&sv.ListenAddress, INADDR_ANY, port);
    DWORD err = call(h, OVPN_IOCTL_MP_START_VPN, &sv, sizeof(sv), &svOut, sizeof(svOut));
    if (err) {
        fprintf(stderr, "MP_START_VPN on port %u refused: error %lu\n", port, err);
        return 1;
    }

    OVPN_STATS before, now;
    memset(&before, 0, sizeof(before));
    call(h, OVPN_IOCTL_GET_STATS, NULL, 0, &before, sizeof(before));
    printf("== listening on udp/%u for %ds\n", port, seconds);
    fflush(stdout);

    for (int i = 0; i < seconds; i++) {
        Sleep(1000);
        memset(&now, 0, sizeof(now));
        if (call(h, OVPN_IOCTL_GET_STATS, NULL, 0, &now, sizeof(now)))
            continue;
        LONG inData = now.LostInDataPackets - before.LostInDataPackets;
        LONG inCtrl = now.LostInControlPackets - before.LostInControlPackets;
        LONG rxData = now.ReceivedDataPackets - before.ReceivedDataPackets;
        LONG rxCtrl = now.ReceivedControlPackets - before.ReceivedControlPackets;
        if (inData || inCtrl || rxData || rxCtrl) {
            printf("  t+%02ds  lost-in data %ld ctrl %ld   received data %ld ctrl %ld\n",
                   i + 1, inData, inCtrl, rxData, rxCtrl);
            fflush(stdout);
        }
    }

    memset(&now, 0, sizeof(now));
    call(h, OVPN_IOCTL_GET_STATS, NULL, 0, &now, sizeof(now));
    printf("== totals: lost-in data %ld ctrl %ld, received data %ld ctrl %ld\n",
           now.LostInDataPackets - before.LostInDataPackets,
           now.LostInControlPackets - before.LostInControlPackets,
           now.ReceivedDataPackets - before.ReceivedDataPackets,
           now.ReceivedControlPackets - before.ReceivedControlPackets);
    return 0;
}

// Stage one of the float question: does the driver move a peer's transport address to
// the source address of a packet, even when that address is the machine's own? The peer
// gets a key we choose, so a packet crafted on another machine decrypts here, and the
// float decision runs on real, authenticated traffic rather than on garbage.
//
// The key is fixed and public on purpose - it is a probe, not a secret - and the sender
// has to use the same bytes. See tests/ioctl/float-probe.py.
#define PROBE_PEER_ID 1

static int run_floatprobe(HANDLE h, int seconds, USHORT port, ULONG peerAddr, USHORT peerPort)
{
    OVPN_SET_MODE sm;
    sm.Mode = OVPN_MODE_MP;
    if (call(h, OVPN_IOCTL_SET_MODE, &sm, sizeof(sm), NULL, 0)) {
        fprintf(stderr, "SET_MODE(MP) refused\n");
        return 1;
    }

    OVPN_MP_START_VPN sv, svOut;
    memset(&sv, 0, sizeof(sv));
    fill_sockaddr((SOCKADDR_IN*)&sv.ListenAddress, INADDR_ANY, port);
    DWORD err = call(h, OVPN_IOCTL_MP_START_VPN, &sv, sizeof(sv), &svOut, sizeof(svOut));
    if (err) {
        fprintf(stderr, "MP_START_VPN on port %u refused: error %lu\n", port, err);
        return 1;
    }

    OVPN_MP_NEW_PEER np;
    memset(&np, 0, sizeof(np));
    fill_sockaddr((SOCKADDR_IN*)&np.Local, INADDR_ANY, port);
    fill_sockaddr((SOCKADDR_IN*)&np.Remote, peerAddr, peerPort);
    np.VpnAddr4.S_un.S_addr = htonl(0x0A580002);
    np.PeerId = PROBE_PEER_ID;
    err = call(h, OVPN_IOCTL_MP_NEW_PEER, &np, sizeof(np), NULL, 0);
    if (err) {
        fprintf(stderr, "MP_NEW_PEER refused: error %lu\n", err);
        return 1;
    }

    OVPN_CRYPTO_DATA_V2 cd;
    memset(&cd, 0, sizeof(cd));
    cd.V1.PeerId = PROBE_PEER_ID;
    cd.V1.KeySlot = OVPN_KEY_SLOT_PRIMARY;
    cd.V1.CipherAlg = OVPN_CIPHER_ALG_AES_GCM;
    cd.V1.KeyId = 0;
    memset(cd.V1.Decrypt.Key, 0x11, 32);
    cd.V1.Decrypt.KeyLen = 32;
    memset(cd.V1.Decrypt.NonceTail, 0x22, 8);
    memset(cd.V1.Encrypt.Key, 0x33, 32);
    cd.V1.Encrypt.KeyLen = 32;
    memset(cd.V1.Encrypt.NonceTail, 0x44, 8);
    err = call(h, OVPN_IOCTL_NEW_KEY_V2, &cd, sizeof(cd), NULL, 0);
    if (err) {
        fprintf(stderr, "MP_NEW_KEY refused: error %lu\n", err);
        return 1;
    }

    printf("== peer %d at %lu.%lu.%lu.%lu:%u, AES-256-GCM key 0x11.., nonce tail 0x22..\n",
           PROBE_PEER_ID, (peerAddr >> 24) & 0xFF, (peerAddr >> 16) & 0xFF,
           (peerAddr >> 8) & 0xFF, peerAddr & 0xFF, peerPort);
    printf("== listening on udp/%u for %ds; send the probe now\n", port, seconds);
    fflush(stdout);

    OVPN_STATS before, now;
    memset(&before, 0, sizeof(before));
    call(h, OVPN_IOCTL_GET_STATS, NULL, 0, &before, sizeof(before));

    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)seconds * 1000;
    LONG floats = 0, decrypted = 0;
    while (GetTickCount64() < deadline) {
        OVPN_NOTIFY_EVENT ev;
        memset(&ev, 0, sizeof(ev));
        if (call(h, OVPN_IOCTL_NOTIFY_EVENT, NULL, 0, &ev, sizeof(ev)) == 0) {
            if (ev.Cmd == OVPN_CMD_FLOAT_PEER) {
                SOCKADDR_IN* sa = (SOCKADDR_IN*)&ev.FloatAddress;
                ULONG a = ntohl(sa->sin_addr.s_addr);
                printf("  FLOAT peer %d -> %lu.%lu.%lu.%lu:%u\n", ev.PeerId,
                       (a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                       ntohs(sa->sin_port));
                floats++;
            } else {
                printf("  notify cmd %d peer %d\n", (int)ev.Cmd, ev.PeerId);
            }
            fflush(stdout);
        }

        memset(&now, 0, sizeof(now));
        if (call(h, OVPN_IOCTL_GET_STATS, NULL, 0, &now, sizeof(now)) == 0) {
            LONG rx = now.ReceivedDataPackets - before.ReceivedDataPackets;
            if (rx != decrypted) {
                printf("  %ld packet(s) decrypted (lost-in %ld)\n", rx,
                       now.LostInDataPackets - before.LostInDataPackets);
                decrypted = rx;
                fflush(stdout);
            }
        }
    }

    printf("== %ld decrypted, %ld float(s)%s\n", decrypted, floats,
           floats ? "" : " <- the driver kept the peer where it was");
    OVPN_MP_DEL_PEER dp;
    dp.PeerId = PROBE_PEER_ID;
    call(h, OVPN_IOCTL_MP_DEL_PEER, &dp, sizeof(dp), NULL, 0);
    return 0;
}

// The same cycle against the point-to-point surface, for releases that predate multipeer.
// They have no MP ioctls, and a P2P write carries no sockaddr prefix - the peer's own
// remote address is where everything goes. Point that at the driver's own listen port and
// two different threads can hold the lock shared across a send:
//
//   the userspace write, as everywhere else, and - in those releases only - the keepalive
//   ping, which holds device->SpinLock across OvpnSocketSend (1.3.3 timer.cpp:65..88).
//
// The ping is the interesting one. It runs as a timer DPC, so unlike the write it is not
// dispatched from the sequential queue and an ioctl can overlap it freely. NEW_KEY,
// SWAP_KEYS and SET_PEER each take the lock exclusive even when they go on to fail, so
// hammering them supplies thread B at whatever rate the machine allows.
static DWORD WINAPI thread_p2p_pressure(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    while (!g_stop) {
        switch (trnd(&a->seed) % 4) {
        case 3: {
            // Re-create the peer, which swaps the transport socket underneath the
            // writer: the teardown path has to stop new senders and wait for the
            // ones inside a send before it closes the old socket.
            OVPN_NEW_PEER np;
            memset(&np, 0, sizeof(np));
            fill_sockaddr((SOCKADDR_IN*)&np.Local, INADDR_ANY, a->port);
            fill_sockaddr((SOCKADDR_IN*)&np.Remote, 0x7F000001, a->port);
            np.Proto = OVPN_PROTO_UDP;
            call(a->h, OVPN_IOCTL_NEW_PEER, &np, sizeof(np), NULL, 0);
            break;
        }
        case 0: {
            OVPN_SET_PEER sp;
            sp.KeepaliveInterval = 1;       /* keep the ping coming */
            sp.KeepaliveTimeout = 0;
            sp.MSS = (LONG)(1000 + trnd(&a->seed) % 400);
            call(a->h, OVPN_IOCTL_SET_PEER, &sp, sizeof(sp), NULL, 0);
            break;
        }
        case 1: {
            OVPN_CRYPTO_DATA cd;
            memset(&cd, 0, sizeof(cd));
            cd.CipherAlg = OVPN_CIPHER_ALG_AES_GCM;
            cd.KeySlot = OVPN_KEY_SLOT_PRIMARY;
            cd.Encrypt.KeyLen = 32;
            cd.Decrypt.KeyLen = 32;
            call(a->h, OVPN_IOCTL_NEW_KEY, &cd, sizeof(cd), NULL, 0);
            break;
        }
        default:
            call(a->h, OVPN_IOCTL_SWAP_KEYS, NULL, 0, NULL, 0);
            break;
        }
        InterlockedIncrement(&g_ops[a->slot]);
    }
    return 0;
}

static int run_p2pselfsend(HANDLE h, int seconds, USHORT port)
{
    OVPN_NEW_PEER np;
    memset(&np, 0, sizeof(np));
    fill_sockaddr((SOCKADDR_IN*)&np.Local, INADDR_ANY, port);
    fill_sockaddr((SOCKADDR_IN*)&np.Remote, 0x7F000001, port);   /* itself */
    np.Proto = OVPN_PROTO_UDP;
    DWORD err = call(h, OVPN_IOCTL_NEW_PEER, &np, sizeof(np), NULL, 0);
    if (err) {
        fprintf(stderr, "NEW_PEER refused: error %lu\n", err);
        return 1;
    }

    /* a usable key, or the keepalive ping is never encrypted and never sent */
    OVPN_CRYPTO_DATA cd;
    memset(&cd, 0, sizeof(cd));
    cd.CipherAlg = OVPN_CIPHER_ALG_AES_GCM;
    cd.KeySlot = OVPN_KEY_SLOT_PRIMARY;
    cd.Encrypt.KeyLen = 32;
    cd.Decrypt.KeyLen = 32;
    err = call(h, OVPN_IOCTL_NEW_KEY, &cd, sizeof(cd), NULL, 0);
    if (err) {
        fprintf(stderr, "NEW_KEY refused: error %lu\n", err);
    }
    call(h, OVPN_IOCTL_START_VPN, NULL, 0, NULL, 0);

    OVPN_SET_PEER sp;
    sp.KeepaliveInterval = 1;       /* ping itself once a second */
    sp.KeepaliveTimeout = 0;
    sp.MSS = 0;
    err = call(h, OVPN_IOCTL_SET_PEER, &sp, sizeof(sp), NULL, 0);
    if (err) {
        fprintf(stderr, "SET_PEER refused: error %lu\n", err);
    }

    printf("== p2p: peer remote is 127.0.0.1:%u, the driver's own listen port\n", port);
    printf("   keepalive 1s, so the driver pings itself while ioctls take the lock\n");
    printf("   an unfixed driver deadlocks here and the machine stops answering\n");
    fflush(stdout);

    ThreadArg pressure;
    pressure.h = h;
    pressure.seed = g_seed ? g_seed : 1;
    pressure.slot = 0;
    pressure.port = port;
    HANDLE pressureThread = CreateThread(NULL, 0, thread_p2p_pressure, &pressure, 0, NULL);

    /* writes too: in p2p the payload is the whole packet, no sockaddr prefix */
    unsigned char pkt[64];
    memset(pkt, 0x42, sizeof(pkt));
    pkt[0] = (unsigned char)(OVPN_OP_DATA_V2 << OVPN_OPCODE_SHIFT);
    pkt[1] = pkt[2] = pkt[3] = 0;

    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)seconds * 1000;
    LONG writes = 0;
    ULONGLONG nextTick = GetTickCount64() + 5000;
    while (GetTickCount64() < deadline) {
        rw_dev(h, pkt, (DWORD)sizeof(pkt), true, NULL);
        writes++;
        if (GetTickCount64() >= nextTick) {
            printf("  alive: %ld writes, %ld ioctls\n", writes, g_ops[0]);
            fflush(stdout);
            nextTick += 5000;
        }
    }

    InterlockedExchange(&g_stop, 1);
    if (pressureThread != NULL) {
        WaitForSingleObject(pressureThread, 30000);
        CloseHandle(pressureThread);
    }
    printf("== %ld writes, %ld exclusive-taking ioctls, no deadlock\n", writes, g_ops[0]);
    call(h, OVPN_IOCTL_DEL_PEER, NULL, 0, NULL, 0);
    return 0;
}

static int run_churn(HANDLE h, int seconds, USHORT port, bool packets)
{
    OVPN_SET_MODE sm;
    sm.Mode = OVPN_MODE_MP;
    if (call(h, OVPN_IOCTL_SET_MODE, &sm, sizeof(sm), NULL, 0)) {
        fprintf(stderr, "SET_MODE(MP) refused; is something else holding the device?\n");
        return 1;
    }

    OVPN_MP_START_VPN sv;
    memset(&sv, 0, sizeof(sv));
    fill_sockaddr((SOCKADDR_IN*)&sv.ListenAddress, INADDR_ANY, port);
    // It hands the bound address back, so it wants an output buffer too: with port 0 the
    // caller learns which port the driver actually got.
    OVPN_MP_START_VPN svOut;
    DWORD err = call(h, OVPN_IOCTL_MP_START_VPN, &sv, sizeof(sv), &svOut, sizeof(svOut));
    if (err) {
        fprintf(stderr, "MP_START_VPN on port %u refused: error %lu\n", port, err);
        return 1;
    }
    bool tx = configure_adapter();
    printf("== churning for %ds, %d peer ids, listening on udp/%u%s\n", seconds, PEER_SPACE, port,
           tx ? "" : " (no adapter address: the transmit path will stay idle)");

    // The last two carry packets. Without them the ioctl threads have the driver to
    // themselves, which is how to tell a slow ioctl path apart from one that is simply
    // being starved by the data path.
    static const struct { LPTHREAD_START_ROUTINE fn; const char* name; bool packets; } kThreads[] = {
        { thread_peers,   "peers",   false },
        { thread_keys,    "keys",    false },
        { thread_routes,  "routes",  false },
        { thread_stats,   "stats",   false },
        { thread_notify,  "notify",  false },
        { thread_ctrl_rx, "ctrl-rx", false },
        { thread_ctrl_tx, "ctrl-tx", true  },
        { thread_traffic, "traffic", true  },
        { thread_tx,      "tx",      true  },
    };
    const int n = (int)(sizeof(kThreads) / sizeof(kThreads[0]));

    HANDLE th[12];
    ThreadArg args[12];
    int started = 0;
    for (int i = 0; i < n; i++) {
        if (kThreads[i].packets && !packets)
            continue;
        args[i].h = h;
        args[i].seed = g_seed + (unsigned)i * 2654435761u;
        args[i].slot = i;
        args[i].port = port;
        th[started++] = CreateThread(NULL, 0, kThreads[i].fn, &args[i], 0, NULL);
    }

    Sleep((DWORD)seconds * 1000);
    InterlockedExchange(&g_stop, 1);
    WaitForMultipleObjects(started, th, TRUE, 30000);
    for (int i = 0; i < started; i++)
        CloseHandle(th[i]);

    for (int i = 0; i < n; i++) {
        if (kThreads[i].packets && !packets)
            continue;
        printf("  %-8s %8ld ops\n", kThreads[i].name, g_ops[i]);
    }
    printf("  control      %8ld packets read, %ld writes accepted%s\n",
           g_ctrlRead, g_ctrlWritten,
           g_ctrlRead ? "" : " <- no control packet ever reached a read");
    printf("  expired      %8ld peers timed out by the driver%s\n", g_expired,
           g_expired ? "" : " <- the timer path was never reached");
    printf("  epoch keys   %8ld installed, %ld refused%s\n",
           g_epochKeysTaken, g_epochKeysRefused,
           g_epochKeysTaken ? "" : " <- the epoch path was never reached");
    unsigned pendedTotal = 0;
    for (size_t i = 0; i < kIoctlCount; i++) {
        LONG stuck = g_pended[pended_slot(kIoctls[i].code)];
        if (stuck == 0)
            continue;
        pendedTotal += (unsigned)stuck;
        printf("  %-15s %8ld calls pended past their deadline%s\n", kIoctls[i].name, stuck,
               kIoctls[i].blocking ? " (parks by design)" : " <- not meant to block");
    }
    printf("== %u calls pended past their deadline\n", pendedTotal);

    // Tear the peers down, so what is left at exit is the driver's own state rather than
    // ours: a leak then shows up when the driver unloads.
    for (int id = 0; id < PEER_SPACE; id++) {
        OVPN_MP_DEL_PEER dp;
        dp.PeerId = id;
        call(h, OVPN_IOCTL_MP_DEL_PEER, &dp, sizeof(dp), NULL, 0);
    }
    return 0;
}


static int run_mutate(HANDLE h, OVPN_MODE mode)
{
    Counters total = { 0, 0, 0, 0 };
    // Pin the mode first: the driver refuses ioctls belonging to the other personality,
    // so without this the results depend on whichever SET_MODE mutation last succeeded.
    OVPN_SET_MODE sm;
    sm.Mode = mode;
    DWORD merr = call(h, OVPN_IOCTL_SET_MODE, &sm, sizeof(sm), NULL, 0);
    printf("== mutating %zu ioctls in %s mode, seed %u%s\n", kIoctlCount,
           mode == OVPN_MODE_MP ? "MP" : "P2P", g_seed,
           merr ? " (SET_MODE refused; mode is whatever it already was)" : "");

    for (size_t i = 0; i < kIoctlCount; i++) {
        // leave the mode where it was pinned
        if (kIoctls[i].code == OVPN_IOCTL_SET_MODE)
            continue;
        Counters c = { 0, 0, 0, 0 };
        mutate_sizes(h, kIoctls[i], c);
        mutate_pointers(h, kIoctls[i], c);
        mutate_values(h, kIoctls[i], c);
        printf("  %-15s %4u calls, %4u refused, %4u accepted, %4u pended\n",
               kIoctls[i].name, c.calls, c.refused, c.accepted, c.pended);
        total.calls += c.calls;
        total.refused += c.refused;
        total.accepted += c.accepted;
    }

    printf("== %u calls, %u refused, %u accepted, %u pended\n",
           total.calls, total.refused, total.accepted, total.pended);
    return 0;
}

// Unknown control codes, which should be refused by the dispatch's default arm.
static int run_unknown(HANDLE h)
{
    unsigned char buf[256];
    memset(buf, 0x41, sizeof(buf));
    unsigned accepted = 0, calls = 0;

    for (DWORD fn = 0; fn < 64; fn++) {
        DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, fn, METHOD_BUFFERED, FILE_ANY_ACCESS);
        bool known = false;
        for (size_t i = 0; i < kIoctlCount; i++)
            if (kIoctls[i].code == code) { known = true; break; }
        if (known)
            continue;
        DWORD err = call(h, code, buf, sizeof(buf), buf, sizeof(buf));
        calls++;
        if (!err) {
            accepted++;
            printf("  ! unknown function %lu accepted\n", fn);
        }
    }
    printf("== %u unknown codes, %u accepted\n", calls, accepted);
    return 0;
}

int main(int argc, char** argv)
{
    const char* mode = "mutate";
    int seconds = 30;
    int port = 11199;
    bool packets = true;
    ULONG peerAddr = 0x7F000001;    // floatprobe's peer, overridden with --peer
    USHORT peerPort = 40000;
    g_seed = (unsigned)GetTickCount();

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--seed") && i + 1 < argc) g_seed = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        // --no-churn is the same switch seen from selfsend: no peer thread, so nothing
        // ever asks for the lock exclusive
        else if (!strcmp(argv[i], "--no-packets") || !strcmp(argv[i], "--no-churn")) packets = false;
        else if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            // a.b.c.d:port - where floatprobe says its peer lives to begin with
            char* spec = argv[++i];
            char* colon = strrchr(spec, ':');
            if (colon != NULL) {
                *colon = 0;
                peerPort = (USHORT)atoi(colon + 1);
            }
            IN_ADDR parsed;
            if (InetPtonA(AF_INET, spec, &parsed) == 1)
                peerAddr = ntohl(parsed.S_un.S_addr);
        }
        else {
            fprintf(stderr, "usage: %s [--mode mutate|mutate-p2p|unknown|churn|selfsend|ctrlself|p2pselfsend|listen|floatprobe] [--seed N] [--seconds N] [--port N] [--no-packets|--no-churn]\n", argv[0]);
            return 2;
        }
    }
    if (g_seed == 0)
        g_seed = 1;     // xorshift never leaves zero

    printf("seed %u (pass --seed %u to repeat this run)\n", g_seed, g_seed);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    HANDLE h = open_device();
    if (h == INVALID_HANDLE_VALUE)
        return 1;

    int rc;
    if (!strcmp(mode, "mutate"))
        rc = run_mutate(h, OVPN_MODE_MP);
    else if (!strcmp(mode, "mutate-p2p"))
        rc = run_mutate(h, OVPN_MODE_P2P);
    else if (!strcmp(mode, "unknown"))
        rc = run_unknown(h);
    else if (!strcmp(mode, "churn"))
        rc = run_churn(h, seconds, (USHORT)port, packets);
    else if (!strcmp(mode, "selfsend"))
        rc = run_selfsend(h, seconds, (USHORT)port, packets, false);
    else if (!strcmp(mode, "p2pselfsend"))
        rc = run_p2pselfsend(h, seconds, (USHORT)port);
    else if (!strcmp(mode, "ctrlself"))
        rc = run_selfsend(h, seconds, (USHORT)port, packets, true);
    else if (!strcmp(mode, "listen"))
        rc = run_listen(h, seconds, (USHORT)port);
    else if (!strcmp(mode, "floatprobe"))
        rc = run_floatprobe(h, seconds, (USHORT)port, peerAddr, peerPort);
    else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        rc = 2;
    }

    CloseHandle(h);
    printf("done\n");
    return rc;
}
