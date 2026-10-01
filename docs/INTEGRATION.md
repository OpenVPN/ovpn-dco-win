# Using ovpn-dco-win in your VPN client

This guide is for teams who build a VPN client for Windows on the OpenVPN protocol and
want the speed of ovpn-dco-win in it. It covers what the driver needs from your server,
how to ship it, and — if you have your own OpenVPN implementation — how to drive it.

Everything here describes the driver in this repository; the API is declared in
[`uapi/ovpn-dco.h`](../uapi/ovpn-dco.h).

---

## First: which kind of client do you have?

**Your client is built on OpenVPN 2.6 or newer, or on OpenVPN 3 Core.** Then OpenVPN
already speaks to the driver for you, and you write no driver code at all. You only need
to [ship the driver](#shipping-the-driver), create an adapter, and make sure your
[server is compatible](#what-your-server-must-do). Skip the API section.

**You have your own implementation of the OpenVPN protocol.** Then your code keeps doing
the handshake (TLS) and key negotiation, and hands the data traffic to the driver
through the [API](#driving-the-driver-yourself). The driver does not do TLS; it only
encrypts, decrypts and moves packets once you give it keys.

---

## What your server must do

The driver only handles the modern part of the OpenVPN protocol. A connection works with
DCO only if:

* **the data cipher is AEAD**: AES-128/192/256-GCM, or ChaCha20-Poly1305 (on Windows 11
  and Server 2022 or newer). Old CBC ciphers such as `BF-CBC` or `AES-256-CBC` are not
  supported. On an OpenVPN server, list only supported ciphers in `--data-ciphers`;
* **there is no compression**: `--allow-compression no` on the client, and the server
  pushes no `compress` or `comp-lzo`. A server that still has to serve old clients can use
  `--compress migrate`;
* **there is no `--fragment`**, and the client connects without an HTTP or SOCKS proxy;
* **the server pushes a `peer-id`**, so data packets use the `DATA_V2` format. Every
  OpenVPN server since 2.4 does this for a client that announces DATA_V2 support (the
  `IV_PROTO_DATA_V2` bit in the `IV_PROTO` peer-info it sends during the handshake). If
  no `peer-id` was pushed, do not use the driver for that connection. OpenVPN servers
  running DCO themselves drop clients that do not announce DATA_V2;
* the connection uses TLS, not a static key.

OpenVPN clients check this themselves and silently fall back to their slower built-in
data channel when something does not fit — look for `disables data channel offload` in
the log. If you implement the protocol yourself, make the same checks before you use the
driver.

---

## Shipping the driver

### The files

Take them from [GitHub Releases](https://github.com/OpenVPN/ovpn-dco-win/releases):

* `ovpn-dco-win-<version>-<amd64|arm64|x86>.zip` — the driver, signed by Microsoft, in a
  `win10` folder (Windows 10) and a `win11` folder (Windows 11, Server 2022 and newer);
* `ovpn-dco-<arch>.msm` — a merge module for your MSI, which installs the right one;
* `sampleinstaller-<arch>.msi` — a minimal MSI using the merge module.

You may redistribute these files, but do not change them: any change breaks Microsoft's
signature, and Windows will refuse to load the driver.

### Installing

**With an MSI**, add the merge module. Set the `NETADAPTERCX21` property on Windows 11 /
Server 2022 and newer so it picks the `win11` driver; [`msm/sampleinstaller.wxs`](../msm/sampleinstaller.wxs)
shows the file search on `advapi32.dll` that does it.

**Without an MSI**, from an administrator process:

```
pnputil /add-driver ovpn-dco.inf /install
```

### Creating an adapter

Each VPN connection needs one virtual adapter with hardware ID `ovpn-dco`. Create adapters
at install time, with administrator rights; your app then only opens them. With SetupAPI,
the sequence OpenVPN's `tapctl create --hwid ovpn-dco` uses
([`tap_create_adapter()`](https://github.com/OpenVPN/openvpn/blob/master/src/tapctl/tap.c)) is:

1. `SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, ...)` and `SetupDiClassNameFromGuid`;
2. `SetupDiCreateDeviceInfo(..., DICD_GENERATE_ID, ...)` — a new root-enumerated device;
3. `SetupDiSetDeviceRegistryProperty(..., SPDRP_HARDWAREID, ...)` with `ovpn-dco` followed
   by two NULs (a multi-string);
4. `SetupDiCallClassInstaller(DIF_REGISTERDEVICE, ...)`;
5. `DiInstallDevice(...)` with no driver given, so Windows picks the installed ovpn-dco-win;
6. on failure, `DIF_REMOVE` to clean up.

To remove one, `DIF_REMOVE` on that device. While testing, `devcon install ovpn-dco.inf
ovpn-dco` from the WDK does the same in one command.

### Living alongside other VPN apps

Other products on the same PC may ship ovpn-dco-win too — OpenVPN itself does. Windows
keeps one copy of a driver in its driver store and uses the newest version installed, so:

* **don't uninstall the driver package** when your app is removed — another app may rely
  on it. Remove only the adapters you created;
* each adapter can be used by one app at a time (see below), so use your own adapters,
  not someone else's.

---

## Who may do what

| Action | Needs administrator rights? |
| --- | --- |
| Install the driver, create or remove adapters | yes — do it in your installer |
| Open an adapter and drive the tunnel (every call below) | **no** — any process may |
| Set the adapter's IP address, routes and DNS | yes |

So a typical design runs the tunnel in your normal app, and the network configuration in
a small privileged service — which is what OpenVPN's interactive service does.

---

## Driving the driver yourself

The snippets below need `uapi/ovpn-dco.h` (which includes `winsock2.h` and `ws2ipdef.h`)
and, for finding adapters, `setupapi.lib` and `cfgmgr32.lib`. Steps 1 to 3 are also a
complete program in [`example/example-client.c`](example/example-client.c), which runs without
administrator rights. Build it with CMake from a Visual Studio developer prompt:
`cmake -S docs/example -B build && cmake --build build`.

This is the sequence for a **client** (one server, "point-to-point" mode). All calls are
`DeviceIoControl`, `ReadFile` or `WriteFile` on one handle. The steps follow what
OpenVPN's [`dco_win.c`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/dco_win.c)
does, which is the best working reference.

### 1. Check the driver version

Open the version device — it is not exclusive, so this works even while adapters are in
use — and ask:

```c
HANDLE v = CreateFileA("\\\\.\\ovpn-dco-ver", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
OVPN_VERSION ver = { 0 };
DWORD n;
DeviceIoControl(v, OVPN_IOCTL_GET_VERSION, NULL, 0, &ver, sizeof(ver), &n, NULL);
CloseHandle(v);
```

Use the version to decide which features you may use: server (multipeer) mode and epoch
keys (`OVPN_IOCTL_NEW_KEY_V2`) need 2.4.0 or newer, per-peer statistics
(`OVPN_IOCTL_GET_PEER_STATS`) 2.7.0 or newer.

### 2. Open your adapter

Find the adapter's device interface path:

1. list the network devices: `SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT)`;
2. keep those whose `SPDRP_HARDWAREID` contains `ovpn-dco`;
3. get the device's instance ID: `SetupDiGetDeviceInstanceId`;
4. list its interfaces: `CM_Get_Device_Interface_List(&GUID_DEVINTERFACE_NET, instanceId, ...)`,
   and take the one whose path **ends in `\ovpn-dco`**.

([`example/example-client.c`](example/example-client.c) does exactly this.) Open it for overlapped I/O:

```c
HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
```

* The handle is **exclusive**: while you hold it, nobody else can open the adapter
  (they get `ERROR_ACCESS_DENIED`).
* **Closing the handle ends the tunnel** — the driver drops the peer, closes its socket
  and disconnects the adapter. That is also what happens if your process crashes.
* `\\.\ovpn-dco` also works, but only reaches the first adapter on the machine; it is meant
  for test tools.

### 3. Tell it where the server is — before the handshake

```c
OVPN_NEW_PEER peer = { 0 };
peer.Proto = OVPN_PROTO_UDP;              /* or OVPN_PROTO_TCP */
peer.Remote.Addr4 = server;               /* SOCKADDR_IN, or Addr6 for IPv6 */
peer.Local.Addr4.sin_family = AF_INET;    /* address 0, port 0: let Windows choose */
DeviceIoControl(h, OVPN_IOCTL_NEW_PEER, &peer, sizeof(peer), NULL, 0, NULL, &ov);
```

The driver now owns the UDP or TCP socket to the server, and **your handshake traffic goes
through the driver too** (next step). For UDP the call completes at once. For TCP it stays
pending until the connection is established, so wait on the `OVERLAPPED` with a timeout.

### 4. Do the handshake through ReadFile and WriteFile

Everything that is not data — the TLS handshake, renegotiations, pushes — is *control
channel* traffic. The driver passes it through untouched:

* **`WriteFile`** one complete OpenVPN control packet to send it to the server. At most
  1500 bytes. Over TCP, the driver adds the 2-byte length prefix itself.
* **`ReadFile`** to receive one. Each completed read is exactly one packet; give it a
  2048-byte buffer. Keep a read pending at all times — packets that arrive with no read
  waiting are queued, but a pending read is also how the driver tells you the connection
  has ended (step 7).

Use overlapped I/O for both. A UDP write completes as soon as the driver has copied it; a
TCP write completes when it is sent.

### 5. Install the keys

When the handshake has produced data channel keys:

```c
OVPN_CRYPTO_DATA c = { 0 };
c.CipherAlg = OVPN_CIPHER_ALG_AES_GCM;    /* or OVPN_CIPHER_ALG_CHACHA20_POLY1305 */
c.KeySlot   = OVPN_KEY_SLOT_PRIMARY;
c.KeyId     = key_id;                     /* the key-id of this key, 0..7 */
c.PeerId    = peer_id;                    /* the peer-id the server pushed */
c.Encrypt.KeyLen = c.Decrypt.KeyLen = 32; /* 16, 24 or 32 for AES-GCM */
memcpy(c.Encrypt.Key, enc_key, 32);  memcpy(c.Encrypt.NonceTail, enc_iv, 8);
memcpy(c.Decrypt.Key, dec_key, 32);  memcpy(c.Decrypt.NonceTail, dec_iv, 8);
DeviceIoControl(h, OVPN_IOCTL_NEW_KEY, &c, sizeof(c), NULL, 0, &n, NULL);
```

For **epoch data keys** use `OVPN_CRYPTO_DATA_V2`, set `CryptoOptions` to
`CRYPTO_OPTIONS_EPOCH`, put the 32-byte epoch key material in `Key`, and call
`OVPN_IOCTL_NEW_KEY_V2`. The driver then derives and rotates the data keys itself.

**Renegotiation:** when a new key is ready, install it in the **secondary** slot, then
call `OVPN_IOCTL_SWAP_KEYS`. The new key becomes primary and is used for sending; the old
one stays secondary and is still accepted for receiving, so packets in flight are not
lost. Received packets are matched to a key by their key-id, from either slot. There is
no call to delete a key; the next swap replaces it.

### 6. Set keepalive, start, and configure the adapter

```c
OVPN_SET_PEER sp = { .KeepaliveInterval = 10, .KeepaliveTimeout = 60, .MSS = 0 };
DeviceIoControl(h, OVPN_IOCTL_SET_PEER, &sp, sizeof(sp), NULL, 0, &n, NULL);
DeviceIoControl(h, OVPN_IOCTL_START_VPN, NULL, 0, NULL, 0, &n, NULL);
```

* **Keepalive** is in seconds. The driver sends OpenVPN's keepalive ping when it has sent
  nothing for `KeepaliveInterval`, and gives up on the server after `KeepaliveTimeout` of
  silence. `-1` leaves a value unchanged. **The driver owns keepalive**: your app must not
  send its own pings on the data channel — OpenVPN switches its pings off when it uses
  DCO.
* **`MSS`**, if not 0, makes the driver clamp the TCP MSS of connections through the
  tunnel to that value; 0 turns clamping off.
* **`START_VPN`** sets the adapter to *connected*. Then give it its IP address, routes and
  DNS with the usual Windows APIs (IP Helper). The adapter can take a moment to appear to
  IP Helper after `START_VPN`; retry briefly if it reports the interface as not found.
* **MTU:** the adapter's maximum is 1500 bytes. Set the interface MTU you want — OpenVPN's
  `tun-mtu`, 1500 by default — with `SetIpInterfaceEntry` (`NlMtu`), up to that maximum.

### 7. While the tunnel runs

* **Statistics:** `OVPN_IOCTL_GET_STATS` returns an `OVPN_STATS` with packet and byte
  counters for the adapter; on 2.7.0 and newer, `OVPN_IOCTL_GET_PEER_STATS` gives them
  per peer.
* **The server went away:** the read you keep pending fails —
  `ERROR_NETNAME_DELETED` when the keepalive timeout expired, `ERROR_CONNECTION_ABORTED`
  when the server closed a TCP connection. Treat either as "connection lost": close the
  handle and reconnect.

### 8. Tear down

Close the handle. To keep the adapter open but drop the server, call
`OVPN_IOCTL_DEL_PEER` instead.

---

## Server mode, briefly

A server sets the adapter to multipeer mode first (`OVPN_IOCTL_SET_MODE` with
`OVPN_MODE_MP`), then opens one UDP socket for all clients (`OVPN_IOCTL_MP_START_VPN`).
Control packets in both directions are prefixed with the client's address (a
`SOCKADDR_IN` or `SOCKADDR_IN6`), and each client becomes a peer with
`OVPN_IOCTL_MP_NEW_PEER`, its own keys, keepalive and routes (`OVPN_IOCTL_MP_*`). The
driver reports clients that time out, disconnect or change address through
`OVPN_IOCTL_NOTIFY_EVENT`, which you keep pending like a read. TCP servers are not
supported yet. OpenVPN 2.7's server is the reference implementation.

---

## When something fails

| You see | It means |
| --- | --- |
| `ERROR_ACCESS_DENIED` on `CreateFile` | another process has the adapter open |
| `ERROR_BAD_COMMAND` on a call | the call is not valid in the current mode — a client call on a server adapter, or the other way round |
| `ERROR_ALREADY_INITIALIZED` | the mode was already set, or the server socket already exists |
| `ERROR_INSUFFICIENT_BUFFER` on `ReadFile` | your read buffer is smaller than the packet; use 2048 bytes |
| `ERROR_NETNAME_DELETED` on a pending read | the keepalive timeout expired |
| `ERROR_CONNECTION_ABORTED` on a pending read | the server closed the TCP connection |

The driver logs much more than error codes can say. Collect a trace as described in
[Troubleshooting](../README.md#troubleshooting) and you will usually see the reason.

## Questions

Open an [issue](https://github.com/OpenVPN/ovpn-dco-win/issues), or write to
[lev@openvpn.net](mailto:lev@openvpn.net).
