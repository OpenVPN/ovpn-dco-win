/*
 * Minimal example for docs/INTEGRATION.md: the first steps of an ovpn-dco-win client.
 *
 *   example-client list                        print the driver version and the adapters
 *   example-client connect <server-ip> <port>  open a free adapter and register the server
 *                                              (IPv4, UDP), as a client does before its
 *                                              handshake
 *
 * It stops there: the TLS handshake, keys and the rest are your OpenVPN implementation's
 * job, as the guide explains. Build with CMake from a Visual Studio developer prompt:
 *
 *   cmake -S . -B build && cmake --build build
 *
 * or directly: cl /W4 /I..\.. example-client.c setupapi.lib cfgmgr32.lib ws2_32.lib
 *
 * This file is MIT licensed, like uapi/ovpn-dco.h.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <initguid.h>
#include <devguid.h>   /* GUID_DEVCLASS_NET */
#include <ndisguid.h>  /* GUID_DEVINTERFACE_NET */
#include <setupapi.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "uapi/ovpn-dco.h"

/* 1. The driver version, from the version device, which any process may open at any time. */
static BOOL
get_version(OVPN_VERSION *ver)
{
    HANDLE h = CreateFileW(L"\\\\.\\ovpn-dco-ver", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return FALSE; /* no driver installed */
    }
    DWORD n = 0;
    BOOL ok = DeviceIoControl(h, OVPN_IOCTL_GET_VERSION, NULL, 0, ver, sizeof(*ver), &n, NULL);
    CloseHandle(h);
    return ok;
}

/* Whether a device has the hardware ID "ovpn-dco" (a REG_MULTI_SZ list). */
static BOOL
is_ovpn_dco(HDEVINFO set, SP_DEVINFO_DATA *dev)
{
    WCHAR ids[512] = { 0 };
    if (!SetupDiGetDeviceRegistryPropertyW(set, dev, SPDRP_HARDWAREID, NULL, (BYTE *)ids,
                                           sizeof(ids) - sizeof(WCHAR), NULL)) {
        return FALSE;
    }
    for (WCHAR *id = ids; *id; id += wcslen(id) + 1) {
        if (_wcsicmp(id, L"ovpn-dco") == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* The path to open for one adapter: its GUID_DEVINTERFACE_NET interface ending in \ovpn-dco. */
static BOOL
get_interface_path(const WCHAR *instance_id, WCHAR *path, size_t path_len)
{
    ULONG len = 0;
    if (CM_Get_Device_Interface_List_SizeW(&len, (LPGUID)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)instance_id,
                                           CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS || len < 2) {
        return FALSE;
    }
    WCHAR *list = calloc(len, sizeof(WCHAR));
    if (list == NULL) {
        return FALSE;
    }
    BOOL found = FALSE;
    if (CM_Get_Device_Interface_ListW((LPGUID)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)instance_id, list, len,
                                      CM_GET_DEVICE_INTERFACE_LIST_PRESENT) == CR_SUCCESS) {
        for (WCHAR *p = list; *p && !found; p += wcslen(p) + 1) {
            const WCHAR *sep = wcsrchr(p, L'\\');
            if (sep && _wcsicmp(sep + 1, L"ovpn-dco") == 0 && wcslen(p) < path_len) {
                wcscpy_s(path, path_len, p);
                found = TRUE;
            }
        }
    }
    free(list);
    return found;
}

/* 2. Find an ovpn-dco adapter that no other process is using, and open it. */
static HANDLE
open_free_adapter(BOOL list_only)
{
    HANDLE result = INVALID_HANDLE_VALUE;
    HDEVINFO set = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) {
        return result;
    }

    SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &dev); i++) {
        WCHAR instance_id[MAX_DEVICE_ID_LEN];
        WCHAR path[1024];
        if (!is_ovpn_dco(set, &dev) ||
            !SetupDiGetDeviceInstanceIdW(set, &dev, instance_id, MAX_DEVICE_ID_LEN, NULL) ||
            !get_interface_path(instance_id, path, ARRAYSIZE(path))) {
            continue;
        }

        /* exclusive: fails with ERROR_ACCESS_DENIED while another process has it */
        HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
        DWORD err = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        wprintf(L"  %ls: %ls\n", instance_id,
                h != INVALID_HANDLE_VALUE ? L"free" : err == ERROR_ACCESS_DENIED ? L"in use" : L"cannot open");

        if (h == INVALID_HANDLE_VALUE) {
            continue;
        }
        if (list_only || result != INVALID_HANDLE_VALUE) {
            CloseHandle(h); /* closing an adapter's handle is what ends a tunnel */
        } else {
            result = h;
        }
    }
    SetupDiDestroyDeviceInfoList(set);
    return result;
}

/* The server as the OVPN_NEW_PEER the driver takes: a numeric IPv4 address and a port (resolving
 * names is your app's job, not the driver's). The local address is "any address, any port". */
static BOOL
parse_server(const char *ip, const char *port, OVPN_NEW_PEER *peer)
{
    ZeroMemory(peer, sizeof(*peer));
    peer->Proto = OVPN_PROTO_UDP;
    peer->Remote.Addr4.sin_family = AF_INET;
    peer->Remote.Addr4.sin_port = htons((unsigned short)atoi(port));
    peer->Local.Addr4.sin_family = AF_INET;
    return inet_pton(AF_INET, ip, &peer->Remote.Addr4.sin_addr) == 1;
}

/* 3. Register the server, over UDP, before the handshake: the handshake travels through the
 * driver's socket too. Over TCP this call stays pending until the connection is up.
 * Returns 0 or the Win32 error. */
static DWORD
new_peer(HANDLE h, const OVPN_NEW_PEER *peer)
{
    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    DWORD n = 0;
    DWORD err = 0;
    if (!DeviceIoControl(h, OVPN_IOCTL_NEW_PEER, (LPVOID)peer, sizeof(*peer), NULL, 0, NULL, &ov)) {
        err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            err = GetOverlappedResult(h, &ov, &n, TRUE) ? 0 : GetLastError();
        }
    }
    CloseHandle(ov.hEvent);
    return err;
}

static int
usage(int status)
{
    printf("usage: example-client list                        driver version and ovpn-dco adapters\n"
           "       example-client connect <server-ip> <port>  open a free adapter and register\n"
           "                                                  the server (IPv4) over UDP\n");
    return status;
}

int
main(int argc, char **argv)
{
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        return usage(0);
    }

    BOOL list = (argc == 2 && strcmp(argv[1], "list") == 0);
    BOOL connect = (argc == 4 && strcmp(argv[1], "connect") == 0);
    if (!list && !connect) {
        return usage(2);
    }

    /* check the address first, so a bad one does not take an adapter */
    OVPN_NEW_PEER peer;
    const char *server = connect ? argv[2] : "";
    if (connect && !parse_server(argv[2], argv[3], &peer)) {
        fprintf(stderr, "%s is not an IPv4 address\n", argv[2]);
        return 1;
    }

    OVPN_VERSION ver = { 0 };
    if (!get_version(&ver)) {
        fprintf(stderr, "ovpn-dco-win is not installed\n");
        return 1;
    }
    printf("ovpn-dco-win %ld.%ld.%ld\n", ver.Major, ver.Minor, ver.Patch);

    printf("adapters:\n");
    HANDLE h = open_free_adapter(list);
    if (list) {
        return 0;
    }
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "no free ovpn-dco adapter\n");
        return 1;
    }

    DWORD err = new_peer(h, &peer);
    if (err != 0) {
        fprintf(stderr, "OVPN_IOCTL_NEW_PEER for %s failed: error %lu\n", server, err);
        CloseHandle(h);
        return 1;
    }
    printf("peer %s registered: now do the handshake with ReadFile/WriteFile on this handle,\n"
           "then OVPN_IOCTL_NEW_KEY, OVPN_IOCTL_SET_PEER and OVPN_IOCTL_START_VPN\n", server);

    CloseHandle(h); /* ends the tunnel */
    return 0;
}
