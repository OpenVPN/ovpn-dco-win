# ovpn-dco-win

![Github Actions](https://github.com/openvpn/ovpn-dco-win/actions/workflows/msbuild.yml/badge.svg)

**A fast VPN driver for Windows.** ovpn-dco-win makes OpenVPN on Windows much faster by
doing the heavy lifting — encrypting and decrypting your traffic — inside Windows itself,
instead of passing every packet back and forth to the OpenVPN program.

*DCO* stands for **D**ata **C**hannel **O**ffload: the "data channel" is the part of a
VPN that carries your actual traffic, and "offload" means handing it to the driver.

---

## I just use OpenVPN. Do I need to do anything?

**No.** If you use OpenVPN 2.6 or newer, you already have it: it is installed together
with OpenVPN and used automatically whenever your connection allows it. OpenVPN Connect
ships it too.

To see which version you have, run `openvpn --version` and look for the line
`DCO version: ...`.

---

## How fast is it?

Measured on our test rig: cloud machines (AWS c6i.4xlarge, 16 cores), Windows Server 2025
at one end and Linux with its built-in OpenVPN driver at the other — or Windows at both
ends for the last two rows — over one VPN tunnel with AES-256-GCM. Each figure is the
average of two full runs.

| What you are doing | 1 connection | 4 connections at once |
| --- | --- | --- |
| Downloading over a UDP tunnel | **5.3 Gbit/s** | **5.5 Gbit/s** |
| Uploading over a UDP tunnel | **5.1 Gbit/s** | **6.0 Gbit/s** |
| Downloading over a TCP tunnel | 4.4 Gbit/s | 4.5 Gbit/s |
| Uploading over a TCP tunnel | 2.7 Gbit/s | 2.7 Gbit/s |
| Windows to Windows, one way | 4.2 Gbit/s | **6.6 Gbit/s** |
| Windows to Windows, the other way | 4.9 Gbit/s | **6.4 Gbit/s** |

For comparison, two Linux machines on the same hardware reach about 5.8 Gbit/s. So a
Windows machine with ovpn-dco-win keeps up with Linux — and with ovpn-dco-win at **both**
ends, four connections go faster than between two Linux machines, because both sides
spread the work over several processor cores.

### It uses all your processor cores

The OpenVPN program works on one processor core, so without DCO a single core encrypts
and decrypts everything you send and receive, and that core is the limit — however many
others your machine has.

ovpn-dco-win spreads this work across the cores, in **both directions**:

* **Receiving:** packets are decrypted on up to 8 cores at once, and still handed to
  Windows in the order they arrived.
* **Sending:** packets are encrypted on up to 8 cores. Each connection inside the tunnel
  (say, a download) always uses the same core, so its packets leave in order. Over a TCP
  tunnel sending stays on one core, because a TCP stream has to go out in order.

A single tunnel — which is what a VPN connection is — gets the speed of several cores
instead of one.

Your own numbers depend on your hardware, your network and the server at the other end.

---

## What it supports

| | |
| --- | --- |
| **Windows** | Windows 10 version 2004 (20H1) and newer, Windows 11, Windows Server 2022 and 2025 |
| **Processors** | x64, ARM64 and x86 |
| **Ciphers** | AES-128-GCM, AES-192-GCM, AES-256-GCM; ChaCha20-Poly1305 on Windows 11 and Server 2022 or newer |
| **As a VPN client** | UDP and TCP |
| **As a VPN server** | UDP (OpenVPN 2.7 or newer) |
| **Key handling** | Regular OpenVPN keys and the newer epoch data keys |

Not yet supported: a TCP server, and a server listening on more than one socket. In those
setups OpenVPN falls back to its regular (slower) data channel automatically.

---

## I build a VPN product. How do I use ovpn-dco-win?

Many VPN providers ship ovpn-dco-win in their own apps. It is free to use; see
[License](#license).

### 1. Get the driver

Download a release from
[GitHub Releases](https://github.com/OpenVPN/ovpn-dco-win/releases). Every release has:

| File | What it is |
| --- | --- |
| `ovpn-dco-win-<version>-<amd64\|arm64\|x86>.zip` | The signed driver: a `win10` and a `win11` folder |
| `ovpn-dco-<arch>.msm` | A Windows Installer merge module, to drop into your own MSI |
| `sampleinstaller-<arch>.msi` | A minimal installer showing how to use the merge module |

**win10 or win11?** Use the `win11` folder on Windows 11 and Windows Server 2022 or
newer, and the `win10` folder on Windows 10. They are the same driver, built against
different versions of Windows' network adapter framework.

### 2. Install it

The easiest way is the **merge module**: add `ovpn-dco-<arch>.msm` to your MSI. It picks
the right build for you if your installer sets the `NETADAPTERCX21` property on Windows
11 / Server 2022 and newer — `msm/sampleinstaller.wxs` shows how, with a file search on
`advapi32.dll`.

Without an MSI, install the driver package from an administrator prompt:

```
pnputil /add-driver ovpn-dco.inf /install
```

### 3. Create a network adapter

The driver works through a virtual network adapter with the hardware ID `ovpn-dco`.
OpenVPN creates one with its `tapctl` tool (`tapctl create --hwid ovpn-dco`); in your own
product you can do the same through the Windows SetupAPI, or for testing with `devcon`
from the WDK:

```
devcon install ovpn-dco.inf ovpn-dco
```

### 4. Talk to it

If your client is built on OpenVPN 2.6+ or OpenVPN 3 Core, OpenVPN already does this for
you — you only ship the driver and create an adapter. If you have your own OpenVPN
implementation, it keeps doing the handshake and key negotiation, and ovpn-dco-win only
moves the encrypted traffic. Your app:

1. **Opens the driver** with `CreateFile`, using the adapter's device interface or the
   name `\\.\ovpn-dco`.
2. **Sets up the connection** with `DeviceIoControl` calls: the peer's address
   (`OVPN_IOCTL_NEW_PEER`), the keys (`OVPN_IOCTL_NEW_KEY_V2`), keepalive
   (`OVPN_IOCTL_SET_PEER`), and then starts the tunnel (`OVPN_IOCTL_START_VPN`).
3. **Exchanges control messages** (the handshake and renegotiation traffic) with
   `ReadFile` / `WriteFile`, preferably asynchronously (`FILE_FLAG_OVERLAPPED`).
4. **Configures the adapter** — IP address and routes — the usual Windows way.

Servers use the `OVPN_IOCTL_MP_*` calls instead, one peer per client, and receive
notifications about clients (for example, a client that timed out) with
`OVPN_IOCTL_NOTIFY_EVENT`.

**The full walkthrough — what your server must support, shipping the driver next to
other VPN apps, every call with example code, and what the errors mean — is in the
[integration guide](docs/INTEGRATION.md).**

Everything is declared in [`uapi/ovpn-dco.h`](uapi/ovpn-dco.h). The best working
examples are:

* **OpenVPN 2** — [`src/openvpn/dco_win.c`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/dco_win.c),
  client and server;
* **OpenVPN 3** — its ovpn-dco-win client;
* [`gui/gui.cpp`](gui/gui.cpp) in this repository — a small test tool that sets up a
  tunnel with a fixed key.

> The test tool uses a fixed key and no handshake. It is for trying the driver out,
> never for real connections.

---

## Troubleshooting

**Collecting driver logs.** The driver logs through Windows' event tracing. From an
administrator prompt, in the folder with `ovpn-dco-win.wprp` (it is in this repository):

```
wpr -start ovpn-dco-win.wprp
... reproduce the problem ...
wpr -stop ovpn-dco-win.etl
```

Open `ovpn-dco-win.etl` with Windows Performance Analyzer, or attach it to a bug report.

<details>
<summary>More ways to see the logs</summary>

* **Live, with TraceView:** run `traceview.exe` as administrator → *File → Create New Log
  Session* → *Manually Entered Control GUID* `4970F9cf-2c0c-4f11-b1cc-e3a1e9958833` →
  *Auto* → *Next* → *Finish*.
* **In a kernel debugger (WinDbg):**
  `tracelog -start MyTrace -guid #4970F9cf-2c0c-4f11-b1cc-e3a1e9958833 -rt -kd`
* **From boot:** run `ovpn-dco-autologger.reg` and reboot. Logs go to
  `%SystemRoot%\System32\LogFiles\WMI\ovpn-dco.etl`.

</details>

**Reporting a bug.** Open an [issue](https://github.com/OpenVPN/ovpn-dco-win/issues) with
your Windows version, the driver version, what you were doing, and the log if you have
one. Please report security problems privately to security@openvpn.net instead.

---

## Building it yourself

You need the Enterprise WDK (EWDK) — releases are built with the **EWDK for Windows
Server 2022 (10.0.20348)**, which still builds for x86. In the EWDK build prompt:

```
msbuild ovpn-dco-win.vcxproj /p:Configuration=Release-Win11 /p:Platform=x64
```

Configurations: `Release` (the win10 build) and `Release-Win11`; `Debug` and
`Debug-Win11` for checked builds. Platforms: `x64`, `ARM64`, `Win32`. Builds are
test-signed; to load one, enable test signing (`bcdedit /set testsigning on`, then
reboot).

---

## How it works, briefly

OpenVPN without DCO reads every packet from a virtual adapter into the OpenVPN program,
encrypts it there and sends it out — two trips across the kernel boundary per packet.
With ovpn-dco-win, the OpenVPN program only handles the handshake and key exchange; the
driver encrypts and decrypts packets as they pass through and sends them over its own UDP
or TCP socket. It does that on several processor cores at once — sending and receiving
alike — where the OpenVPN program is limited to one.

It is written with Microsoft's modern driver frameworks (WDF and NetAdapterCx), which
keeps it smaller and easier to maintain than the classic NDIS drivers it replaces.

---

## License

See [COPYRIGHT.MIT](COPYRIGHT.MIT) and the license headers in the source files.

## Contact

Lev Stipakov — [lev@openvpn.net](mailto:lev@openvpn.net) (`lev__` on #openvpn-devel)
