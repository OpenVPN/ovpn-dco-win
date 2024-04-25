# ovpn-dco-win

![Github Actions](https://github.com/openvpn/ovpn-dco-win/actions/workflows/msbuild.yml/badge.svg)

### Intro

ovpn-dco-win stands for "OpenVPN Data Channel Offload for Windows". It is a modern Windows driver, which functions as virtual network adapter and implements required functionality to handle the OpenVPN data channel. When using ovpn-dco-win, the OpenVPN software doesn't send data traffic back and forth between user and kernel space (for encryption, decryption and routing), but operations on payload take place in Windows kernel. The driver is being developed using modern frameworks - WDF and NetAdapterCx. Because of that, the code is easier to read and maintain comparison to existing NDIS miniport drivers. Speed-wise the new driver performs significantly better comparison to tap-windows6, so it should eliminate the bottleneck which hampers the performance of OpenVPN on Windows.

ovpn-dco-win is a default driver starting from OpenVPN 2.6.

### Installation

You can just install the latest [OpenVPN 2.6 release](https://openvpn.net/community-downloads/), which includes signed driver.


Alternatively you can get releases from [GitHub](https://github.com/OpenVPN/ovpn-dco-win/releases).

You can use devcon tool (available as part of WDK) to install the driver:

```
devcon install ovpn-dco.inf ovpn-dco
```


### ovpn-dco-cli

The project includes ovpn-dco-cli command line tool, which works as development test bed, reference client and API usage example. With that you can setup VPN tunnel between two Windows hosts or
between Windows and Linux host using ./ovpn-cli tool from ovpn-dco Linux project.

To set up Windows <-> Windows tunnel, on first host run:

```
ovpn-dco-cli.exe udp i4 0.0.0.0 1194 192.168.100.200 1194 10.8.0.2 255.255.255.0 10.8.0.1 data64.key 0
```

where "0.0.0.0 1194" local IP address/port to bind the socket, "192.168.100.200 1194" remote address/port, "10.8.0.2" is a local VPN IP.

On the second Windows host run:

```
ovpn-dco-cli.exe udp i4 0.0.0.0 1194 192.168.100.100 1194 10.8.0.1 255.255.255.0 10.8.0.1 data64.key 1
```

Note that remote IP, VPN IP and key direction (last 0/1 digit) are different.

To set up tunnel between Windows and Linux, run on the second (Linux) host:

```
# ip link add dev ovpn0 type ovpn-dco
# ip link set ovpn0 up
# ip link set mtu 1428 dev ovpn0

# ip addr add dev ovpn0 10.8.0.1/24

# tests/ovpn-cli ovpn0 new_peer 1194 0 192.168.100.100 1194 10.8.0.2
# tests/ovpn-cli ovpn0 new_key 0 aes 1 tests/data64.key
```

where 192.168.100.150 is a Linux host IP address, 192.168.100.100 is a Windows host IP address.

After you've established tunnel, you should be able to ping hosts (10.8.0.1 <-> 10.8.0.1) and run iperf tests (iperf3 -s 10.8.0.2 on the first host, iperf3 -c 10.8.0.2 on the second) via VPN tunnel.

Please note that using ovpn-dco-cli tool in production is a very bad idea, because it doesn't do any key negotiation and use a static key (data64.key) instead.


### API Usage

To use the driver, client needs to get file handle by calling CreateFile. One can either use symbolic link or device interface to get the file path. Here is example from ovpn-dco tool (see below):

```
HANDLE h = CreateFileA("\\\\.\\ovpn-dco", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
```

After getting handle, client uses DeviceIOControl and Read/WriteFile calls to set up connection and send/receive control packets. See uapi.h for the list of IOCTL commands and ovpn-dco-cli.cpp on how to use those.

* First, client needs to initialize peer with OVPN_IOCTL_NEW_PEER command. Client passes OVPN_NEW_PEER structure, which contains local/remote IP address/port (either IPv4 or IPv6) and transport protocol (TCP or UDP).

* After initializing peer, client passed cipher algorithm (supported are "none" and "AES-GCM"), crypto keys and peer-id as part of OVPN_CRYPTO_DATA structure using OVPN_IOCTL_NEW_KEY command. Description of openvpn crypto is beyond the scope of this document.

* After setting up crypto, client may set keepalive parameters (OVPN_SET_PEER struct) for the session via OVPN_IOCTL_SET_PEER command. Keepalive interval defines how often to send special keepalive packet in the absence of outgoing data traffic. Keepalive timeout defines when to notify userspace (by completing read request with an error) in the absence of incoming data traffic.

* To start VPN session, client sends OVPN_IOCTL_START_VPN command. This signals driver to start network adapter.

* After starting VPN session, client sets up network adapter (IP address, netmask, gateway) and routing.

To send and receive control channel packets, client uses Read/WriteFile calls. It is recommended to use overlapped IO by passing FILE_FLAG_OVERLAPPED to CreateFile call and OVERLAPPED structure to Read/WriteFile calls. ovpn-dco-cli uses ASIO, which abstracts those low-level details.


### OpenVPN support

ovpn-dco-win driver is used by default OpenVPN starting from 2.6 release.

OpenVPN3 also supports ovpn-dco-win in the latest master branch.

### Logging

Logging is performed via TraceLogging API, which is based on ETW. To see logs on a target machine:

1. Run `traceview.exe` as administrator
2. File -> Create New Log Session
3. Manually Entered Control GUID -> `4970F9cf-2c0c-4f11-b1cc-e3a1e9958833` -> OK
4. Choose Source Of Decoding Information -> Auto -> OK
5. Press "Next" -> "Finish"

To collect logs for analysis:

1. Run administrator command prompt
2. Run `wpr -start ovpn-dco-win.wprp` (wprp file is in driver source tree)
3. Interact with the driver
4. To stop log collection, run `wpr -stop ovpn-dco-win.etl`

The etl file could be opened, for example, by Windows Performance Analyzer (`wpa.exe`).

To see logs in attached debbuger (windbg), use `tracelog.exe` in administrator command prompt:

* `tracelog -start MyTrace -guid #4970F9cf-2c0c-4f11-b1cc-e3a1e9958833 -rt -kd`

If you experience boot issues, you might want to enable AutoLogger session. Run `ovpn-dco-autologger.reg` file, which will create neccessary registry keys, and then reboot.

Driver logs will be stored in `%SystemRoot%\System32\LogFiles\WMI\ovpn-dco.etl`.

### Reproducible builds

Release builds of ovpn-dco-win are reproducible, meaning that when you use the same build environment, you should get the exact same ovpn-dco.sys binary. That way, you can verify that a driver released in binary form is indeed compiled from the source code in this repository. This is useful because Microsoft's driver signing requirements make it difficult to run self-compiled drivers.

Released drivers are built with Windows 11 EWDK (Enterprise Windows Driver Kit). Despite the name, it also works on Windows 10.
You can download it here: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

If you have obtained a ovpn-dco.sys file, you can verify it as follows:

1. Remove the signature from the ovpn-dco.sys file you received: `signtool remove /s ovpn-dco.sys`
2. Clone this repository and check out the version that your file is supposed to be.
3. Mount the Windows 11 EWDK iso image.
4. In Powershell, navigate to the virtual drive and run `LaunchBuildEnv.cmd`.
5. Navigate to the ovpn-dco-win project directory.
6. Build the driver: `msbuild /p:platform=<arch> /p:configuration=release /p:signmode=off ovpn-dco-win.vcxproj /t:Build` where `<arch>` is `Win32`, `x64`, `ARM` or `ARM64`.
7. Check that `<arch>/Release/ovpn-dco.sys` and the file from step 1 have the same SHA256 hash.


### Limitations

* Minimum supported Windows version is Windows 10 20H1.
* Supported cipher are AES-128(-192-256)-GCM and ChaCha20-Poly1305 (starting from Windows 11 / Server 2022)


### Questions

Contact Lev Stipakov [lev@openvpn.net](mailto:lev@openvpn.net) (lev__ on #openvpn-devel)


