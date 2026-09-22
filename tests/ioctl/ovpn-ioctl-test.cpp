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
static LONG g_ops[8];

#define PEER_SPACE 64           // small, so ids are reused constantly

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

static DWORD WINAPI thread_peers(LPVOID p)
{
    ThreadArg* a = (ThreadArg*)p;
    while (!g_stop) {
        int id = (int)(trnd(&a->seed) % PEER_SPACE);
        if (trnd(&a->seed) & 1) {
            OVPN_MP_NEW_PEER np;
            memset(&np, 0, sizeof(np));
            fill_sockaddr((SOCKADDR_IN*)&np.Local, INADDR_ANY, a->port);
            fill_sockaddr((SOCKADDR_IN*)&np.Remote, 0x0A000001 + id, (USHORT)(40000 + id));
            np.VpnAddr4.S_un.S_addr = htonl(0x0A580000 + id);
            np.PeerId = id;
            call(a->h, OVPN_IOCTL_MP_NEW_PEER, &np, sizeof(np), NULL, 0);
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
            k.V1.KeyId = (UCHAR)(trnd(&a->seed) & 7);
            k.V1.Encrypt.KeyLen = 32;
            k.V1.Decrypt.KeyLen = 32;
            for (int i = 0; i < 32; i++) {
                k.V1.Encrypt.Key[i] = (unsigned char)trnd(&a->seed);
                k.V1.Decrypt.Key[i] = (unsigned char)trnd(&a->seed);
            }
            call(a->h, OVPN_IOCTL_NEW_KEY_V2, &k, sizeof(k), NULL, 0);
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
            sp.PeerId = (int)(trnd(&a->seed) % PEER_SPACE);
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
        call(a->h, OVPN_IOCTL_NOTIFY_EVENT, NULL, 0, &ev, sizeof(ev));
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
        UCHAR op = (UCHAR)((OVPN_OP_DATA_V2 << OVPN_OPCODE_SHIFT) | (trnd(&a->seed) & OVPN_KEY_ID_MASK));
        UINT32 hdr = ((UINT32)op << 24) | (peerId & OVPN_PEER_ID_MASK);
        pkt[0] = (unsigned char)(hdr >> 24);
        pkt[1] = (unsigned char)(hdr >> 16);
        pkt[2] = (unsigned char)(hdr >> 8);
        pkt[3] = (unsigned char)hdr;
        for (size_t i = 4; i < sizeof(pkt); i++)
            pkt[i] = (unsigned char)trnd(&a->seed);
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

static int run_churn(HANDLE h, int seconds, USHORT port)
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

    static const struct { LPTHREAD_START_ROUTINE fn; const char* name; } kThreads[] = {
        { thread_peers,   "peers"   },
        { thread_keys,    "keys"    },
        { thread_routes,  "routes"  },
        { thread_stats,   "stats"   },
        { thread_notify,  "notify"  },
        { thread_traffic, "traffic" },
        { thread_tx,      "tx"      },
    };
    const int n = (int)(sizeof(kThreads) / sizeof(kThreads[0]));

    HANDLE th[8];
    ThreadArg args[8];
    for (int i = 0; i < n; i++) {
        args[i].h = h;
        args[i].seed = g_seed + (unsigned)i * 2654435761u;
        args[i].slot = i;
        args[i].port = port;
        th[i] = CreateThread(NULL, 0, kThreads[i].fn, &args[i], 0, NULL);
    }

    Sleep((DWORD)seconds * 1000);
    InterlockedExchange(&g_stop, 1);
    WaitForMultipleObjects(n, th, TRUE, 30000);

    for (int i = 0; i < n; i++) {
        printf("  %-8s %8ld ops\n", kThreads[i].name, g_ops[i]);
        CloseHandle(th[i]);
    }
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
    g_seed = (unsigned)GetTickCount();

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--seed") && i + 1 < argc) g_seed = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s [--mode mutate|mutate-p2p|unknown|churn] [--seed N] [--seconds N] [--port N]\n", argv[0]);
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
        rc = run_churn(h, seconds, (USHORT)port);
    else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        rc = 2;
    }

    CloseHandle(h);
    printf("done\n");
    return rc;
}
