/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2023 Rubicon Communications LLC (Netgate)
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

#include <ntifs.h>

#include "trace.h"
#include "peer.h"
#include "timer.h"
#include "socket.h"

_Use_decl_annotations_
OvpnPeerContext*
OvpnPeerCtxAlloc()
{
    OvpnPeerContext* peer = (OvpnPeerContext*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OvpnPeerContext), 'ovpn');
    if (peer != NULL) {
        RtlZeroMemory(peer, sizeof(OvpnPeerContext));
        InitializeListHead(&peer->ListEntry);
        InterlockedIncrement(&peer->RefCounter);
    }    
    return peer;
}

_Use_decl_annotations_
VOID
OvpnPeerCtxRelease(OvpnPeerContext* peer)
{
    if (InterlockedDecrement(&peer->RefCounter) <= 0) {
        auto peerId = peer->PeerId;
        OvpnPeerCtxFree(peer);
        LOG_INFO("Peer freed", TraceLoggingValue(peerId, "peer-id"));
    }
}

_Use_decl_annotations_
VOID
OvpnPeerCtxFree(OvpnPeerContext* peer)
{
    // Detach the timer while holding the lock to prevent new callbacks
    auto irql = ExAcquireSpinLockExclusive(&peer->SpinLock);
    WDFTIMER timer = peer->Timer;
    peer->Timer = WDF_NO_HANDLE;
    ExReleaseSpinLockExclusive(&peer->SpinLock, irql);

    // Stop the timer outside the lock. Wait only if we're at PASSIVE_LEVEL
    if (timer != WDF_NO_HANDLE) {
        WdfTimerStop(timer, KeGetCurrentIrql() == PASSIVE_LEVEL);
        WdfObjectDelete(timer);
    }

    // Crypto context can be safely cleaned up after the timer is gone
    OvpnCryptoUninit(&peer->CryptoContext);

    ExFreePoolWithTag(peer, 'ovpn');
}

_Use_decl_annotations_
PVOID
OvpnPeerAllocateRoutine(RTL_GENERIC_TABLE* table, CLONG size)
{
    UNREFERENCED_PARAMETER(table);

    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'ovpn');
}

_Use_decl_annotations_
VOID
OvpnPeerFreeRoutine(RTL_GENERIC_TABLE* table, PVOID buffer)
{
    UNREFERENCED_PARAMETER(table);

    ExFreePoolWithTag(buffer, 'ovpn');
}

RTL_GENERIC_COMPARE_RESULTS
OvpnPeerCompareByPeerIdRoutine(RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
{
    UNREFERENCED_PARAMETER(table);

    OvpnPeerContext* peer1 = *(OvpnPeerContext**)first;
    OvpnPeerContext* peer2 = *(OvpnPeerContext**)second;

    if (peer1->PeerId == peer2->PeerId)
        return GenericEqual;
    else if (peer1->PeerId < peer2->PeerId)
        return GenericLessThan;
    else
        return GenericGreaterThan;
}

RTL_GENERIC_COMPARE_RESULTS
OvpnPeerCompareByVPN4Routine(RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
{
    UNREFERENCED_PARAMETER(table);

    OvpnPeerContext* peer1 = *(OvpnPeerContext**)first;
    OvpnPeerContext* peer2 = *(OvpnPeerContext**)second;

    int n = memcmp(&peer1->VpnAddrs.IPv4, &peer2->VpnAddrs.IPv4, sizeof(IN_ADDR));
    if (n == 0)
        return GenericEqual;
    else if (n < 0)
        return GenericLessThan;
    else
        return GenericGreaterThan;
}

RTL_GENERIC_COMPARE_RESULTS
OvpnPeerCompareByVPN6Routine(RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
{
    UNREFERENCED_PARAMETER(table);

    OvpnPeerContext* peer1 = *(OvpnPeerContext**)first;
    OvpnPeerContext* peer2 = *(OvpnPeerContext**)second;

    int n = memcmp(&peer1->VpnAddrs.IPv6, &peer2->VpnAddrs.IPv6, sizeof(IN6_ADDR));
    if (n == 0)
        return GenericEqual;
    else if (n < 0)
        return GenericLessThan;
    else
        return GenericGreaterThan;
}

RTL_GENERIC_COMPARE_RESULTS
OvpnPeerCompareByTransportRoutine(RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
{
    UNREFERENCED_PARAMETER(table);

    OvpnPeerContext* peer1 = *(OvpnPeerContext**)first;
    OvpnPeerContext* peer2 = *(OvpnPeerContext**)second;

    USHORT af1 = peer1->TransportAddrs.Remote.IPv4.sin_family;
    USHORT af2 = peer2->TransportAddrs.Remote.IPv4.sin_family;

    // Compare address families first (AF_INET < AF_INET6)
    if (af1 != af2)
        return (af1 < af2) ? GenericLessThan : GenericGreaterThan;

    if (af1 == AF_INET) {
        const SOCKADDR_IN* a = &peer1->TransportAddrs.Remote.IPv4;
        const SOCKADDR_IN* b = &peer2->TransportAddrs.Remote.IPv4;

        if (a->sin_addr.S_un.S_addr != b->sin_addr.S_un.S_addr)
            return (a->sin_addr.S_un.S_addr < b->sin_addr.S_un.S_addr) ? GenericLessThan : GenericGreaterThan;

        if (a->sin_port != b->sin_port)
            return (a->sin_port < b->sin_port) ? GenericLessThan : GenericGreaterThan;

        return GenericEqual;
    }
    else {
        const SOCKADDR_IN6* a = &peer1->TransportAddrs.Remote.IPv6;
        const SOCKADDR_IN6* b = &peer2->TransportAddrs.Remote.IPv6;

        int cmp = memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(IN6_ADDR));
        if (cmp != 0)
            return (cmp < 0) ? GenericLessThan : GenericGreaterThan;

        if (a->sin6_port != b->sin6_port)
            return (a->sin6_port < b->sin6_port) ?  GenericLessThan : GenericGreaterThan;

        return GenericEqual;
    }
}

_Use_decl_annotations_
NTSTATUS
OvpnAddPeerToTable(POVPN_DEVICE device, RTL_GENERIC_TABLE* table, OvpnPeerContext* peer)
{
    NTSTATUS status;
    BOOLEAN newElem;

    auto irql = ExAcquireSpinLockExclusive(&device->SpinLock);

    RtlInsertElementGenericTable(table, (PVOID)&peer, sizeof(OvpnPeerContext*), &newElem);

    if (newElem) {
        status = STATUS_SUCCESS;
        InterlockedIncrement(&peer->RefCounter);
    }
    else {
        LOG_ERROR("Unable to add new peer");
        status = STATUS_NO_MEMORY;
    }

    ExReleaseSpinLockExclusive(&device->SpinLock, irql);

    return status;
}

_Use_decl_annotations_
VOID
OvpnCleanupPeerTable(POVPN_DEVICE device, RTL_GENERIC_TABLE* peers)
{
    auto irql = ExAcquireSpinLockExclusive(&device->SpinLock);

    while (!RtlIsGenericTableEmpty(peers)) {
        PVOID ptr = RtlGetElementGenericTable(peers, 0);
        OvpnPeerContext* peer = *(OvpnPeerContext**)ptr;
        RtlDeleteElementGenericTable(peers, ptr);

        OvpnPeerCtxRelease(peer);
    }

    ExReleaseSpinLockExclusive(&device->SpinLock, irql);
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnGetFirstPeer(POVPN_DEVICE device)
{
    auto irql = ExAcquireSpinLockShared(&device->SpinLock);

    OvpnPeerContext** ptr = (OvpnPeerContext**)RtlGetElementGenericTable(&device->Peers, 0);
    OvpnPeerContext* peer = ptr ? (OvpnPeerContext*)*ptr : nullptr;

    if (peer != nullptr) {
        InterlockedIncrement(&peer->RefCounter);
    }

    ExReleaseSpinLockShared(&device->SpinLock, irql);

    return peer;
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnFindPeer(POVPN_DEVICE device, INT32 PeerId, BOOLEAN dpc)
{
    OvpnPeerContext* peer = nullptr;
    OvpnPeerContext** ptr = nullptr;

    KIRQL kirql = 0;
    if (dpc) {
        ExAcquireSpinLockSharedAtDpcLevel(&device->SpinLock);
    }
    else {
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
    }

    if (device->Mode == OVPN_MODE_P2P) {
        ptr = (OvpnPeerContext**)RtlGetElementGenericTable(&device->Peers, 0);
    }
    else {
        OvpnPeerContext p{};
        p.PeerId = PeerId;

        auto* pp = &p;
        ptr = (OvpnPeerContext**)RtlLookupElementGenericTable(&device->Peers, &pp);
    }

    peer = ptr ? (OvpnPeerContext*)*ptr : nullptr;

    if (peer) {
        InterlockedIncrement(&peer->RefCounter);
    }

    if (dpc) {
        ExReleaseSpinLockSharedFromDpcLevel(&device->SpinLock);
    }
    else {
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
    }

    return peer;
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnFindPeerVPN4(POVPN_DEVICE device, IN_ADDR addr, BOOLEAN dpc)
{
    OvpnPeerContext* peer = nullptr;
    OvpnPeerContext** ptr = nullptr;

    KIRQL kirql = 0;
    if (dpc) {
        ExAcquireSpinLockSharedAtDpcLevel(&device->SpinLock);
    }
    else {
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
    }

    if (device->Mode == OVPN_MODE_P2P) {
        ptr = (OvpnPeerContext**)RtlGetElementGenericTable(&device->Peers, 0);
    }
    else {
        OvpnPeerContext p{};
        p.VpnAddrs.IPv4 = addr;

        auto* pp = &p;
        ptr = (OvpnPeerContext**)RtlLookupElementGenericTable(&device->PeersByVpn4, &pp);
    }

    peer = ptr ? (OvpnPeerContext*)*ptr : nullptr;
    if (peer) {
        InterlockedIncrement(&peer->RefCounter);
    }

    if (dpc) {
        ExReleaseSpinLockSharedFromDpcLevel(&device->SpinLock);
    }
    else {
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
    }

    return peer;
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnFindPeerVPN6(POVPN_DEVICE device, IN6_ADDR addr, BOOLEAN dpc)
{
    OvpnPeerContext* peer = nullptr;
    OvpnPeerContext** ptr = nullptr;

    KIRQL kirql = 0;
    if (dpc) {
        ExAcquireSpinLockSharedAtDpcLevel(&device->SpinLock);
    }
    else {
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
    }

    if (device->Mode == OVPN_MODE_P2P) {
        ptr = (OvpnPeerContext**)RtlGetElementGenericTable(&device->Peers, 0);
    }
    else {
        OvpnPeerContext p{};
        p.VpnAddrs.IPv6 = addr;

        auto* pp = &p;
        ptr = (OvpnPeerContext**)RtlLookupElementGenericTable(&device->PeersByVpn6, &pp);
    }

    peer = ptr ? (OvpnPeerContext*)*ptr : nullptr;
    if (peer) {
        InterlockedIncrement(&peer->RefCounter);
    }

    if (dpc) {
        ExReleaseSpinLockSharedFromDpcLevel(&device->SpinLock);
    }
    else {
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
    }

    return peer;
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnFindPeerTransport(POVPN_DEVICE device, PSOCKADDR sa, BOOLEAN dpc)
{
    if ((sa->sa_family != AF_INET) && (sa->sa_family != AF_INET6))
        return nullptr;

    OvpnPeerContext* peer = nullptr;
    OvpnPeerContext** ptr = nullptr;

    KIRQL kirql = 0;
    if (dpc) {
        ExAcquireSpinLockSharedAtDpcLevel(&device->SpinLock);
    }
    else {
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
    }

    if (device->Mode == OVPN_MODE_P2P) {
        ptr = (OvpnPeerContext**)RtlGetElementGenericTable(&device->Peers, 0);
    }
    else {
        OvpnPeerContext p{};
        if (sa->sa_family == AF_INET)
            RtlCopyMemory(&p.TransportAddrs.Remote.IPv4, sa, sizeof(SOCKADDR_IN));
        else
            RtlCopyMemory(&p.TransportAddrs.Remote.IPv6, sa, sizeof(SOCKADDR_IN6));

        auto* pp = &p;
        ptr = (OvpnPeerContext**)RtlLookupElementGenericTable(&device->PeersByTransport, &pp);
    }

    peer = ptr ? (OvpnPeerContext*)*ptr : nullptr;
    if (peer) {
        InterlockedIncrement(&peer->RefCounter);
    }

    if (dpc) {
        ExReleaseSpinLockSharedFromDpcLevel(&device->SpinLock);
    }
    else {
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
    }

    return peer;
}

VOID
OvpnDeletePeerFromTable(POVPN_DEVICE device, RTL_GENERIC_TABLE* table, OvpnPeerContext* peer, char* tableName)
{
    OvpnPeerContext* cleanupPeer = nullptr;
    auto peerId = peer->PeerId;
    auto pp = &peer;

    auto kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
    if (RtlDeleteElementGenericTable(table, pp)) {
        LOG_INFO("Peer deleted from the table", TraceLoggingValue(tableName, "table"), TraceLoggingValue(peerId, "peer-id"));
        cleanupPeer = peer;
    }
    else {
        LOG_INFO("Peer not found", TraceLoggingValue(tableName, "table"), TraceLoggingValue(peerId, "peer-id"));
    }
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

    // perform deferred release outside of the lock
    if (cleanupPeer) {
        OvpnPeerCtxRelease(cleanupPeer);
    }
}

static
VOID
OvpnPeerZeroStats(POVPN_STATS stats)
{
    InterlockedExchange(&stats->LostInControlPackets, 0);
    InterlockedExchange(&stats->LostInDataPackets, 0);
    InterlockedExchange(&stats->LostOutControlPackets, 0);
    InterlockedExchange(&stats->LostOutDataPackets, 0);
    InterlockedExchange(&stats->ReceivedControlPackets, 0);
    InterlockedExchange(&stats->ReceivedDataPackets, 0);
    InterlockedExchange(&stats->SentControlPackets, 0);
    InterlockedExchange(&stats->SentDataPackets, 0);
    InterlockedExchange64(&stats->TransportBytesReceived, 0);
    InterlockedExchange64(&stats->TransportBytesSent, 0);
    InterlockedExchange64(&stats->TunBytesReceived, 0);
    InterlockedExchange64(&stats->TunBytesSent, 0);
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerNew(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    POVPN_NEW_PEER peer = NULL;
    NTSTATUS status;

    auto peerCtx = OvpnGetFirstPeer(device);
    if (peerCtx != nullptr) {
        LOG_WARN("Peer already added, deleting existing peer");

        GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPeerDelete(device, 0, OVPN_DEL_PEER_REASON_USERSPACE, FALSE));
        OvpnPeerCtxRelease(peerCtx);
        peerCtx = nullptr;
    }

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_NEW_PEER), (PVOID*)&peer, nullptr));

    if ((peer->Local.Addr4.sin_family != AF_INET) && (peer->Local.Addr4.sin_family != AF_INET6))
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown address family in peer->Local", TraceLoggingValue(peer->Local.Addr4.sin_family, "AF"));
        goto done;
    }

    if ((peer->Remote.Addr4.sin_family != AF_INET) && (peer->Remote.Addr4.sin_family != AF_INET6))
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown address family in peer->Remote", TraceLoggingValue(peer->Remote.Addr4.sin_family, "AF"));
        goto done;
    }

    if ((peer->Proto != OVPN_PROTO_UDP) && (peer->Proto != OVPN_PROTO_TCP))
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown protocol in peer->Proto", TraceLoggingValue((int)peer->Proto, "Proto"));
        goto done;
    }

    POVPN_DRIVER driver = OvpnGetDriverContext(WdfGetDriver());
    PWSK_SOCKET socket = NULL;
    BOOLEAN proto_tcp = peer->Proto == OVPN_PROTO_TCP;
    SIZE_T remoteAddrSize = peer->Remote.Addr4.sin_family == AF_INET ? sizeof(peer->Remote.Addr4) : sizeof(peer->Remote.Addr6);

    peerCtx = OvpnPeerCtxAlloc();
    if (peerCtx == NULL) {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    // assign remote transport address
    if (peer->Remote.Addr4.sin_family == AF_INET) {
        peerCtx->TransportAddrs.Remote.IPv4 = peer->Remote.Addr4;
    }
    else {
        peerCtx->TransportAddrs.Remote.IPv6 = peer->Remote.Addr6;
    }

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnSocketInit(&driver->WskProviderNpi,
        &driver->WskRegistration, peer->Local.Addr4.sin_family, proto_tcp,
        (PSOCKADDR)&peer->Local,
        (PSOCKADDR)&peer->Remote,
        remoteAddrSize, device, &socket, TRUE));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnAddPeerToTable(device, &device->Peers, peerCtx));

    device->Socket.Socket = socket;
    device->Socket.Tcp = proto_tcp;
    RtlZeroMemory(&device->Socket.TcpState, sizeof(OvpnSocketTcpState));
    RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));

    OvpnPeerZeroStats(&device->Stats);

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerCreate(device->WdfDevice, peerCtx, &peerCtx->Timer));

    if (proto_tcp) {
        LOG_IF_NOT_NT_SUCCESS(status = WdfRequestForwardToIoQueue(request, device->PendingNewPeerQueue));
        // start async connect
        status = OvpnSocketTcpConnect(socket, device, (PSOCKADDR)&peer->Remote);
    }

done:
    if (peerCtx != nullptr) {
        OvpnPeerCtxRelease(peerCtx);
    }

    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnMPPeerNew(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    const struct in6_addr ovpn_in6addr_any = { { 0 } };

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_MP_NEW_PEER peer;
    OvpnPeerContext* peerCtx = nullptr;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_MP_NEW_PEER), (PVOID*)&peer, nullptr));

    // check if we already have a peer with the same peer-id
    peerCtx = OvpnFindPeer(device, peer->PeerId, FALSE);
    if (peerCtx != nullptr) {
        status = STATUS_OBJECTID_EXISTS;
        goto done;
    }

    // ensure local/remote address is AF_INET or AF_INET6
    if ((peer->Local.Addr4.sin_family != AF_INET) && (peer->Local.Addr4.sin_family != AF_INET6))
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown address family in peer->Local", TraceLoggingValue(peer->Local.Addr4.sin_family, "AF"));
        goto done;
    }
    if ((peer->Remote.Addr4.sin_family != AF_INET) && (peer->Remote.Addr4.sin_family != AF_INET6))
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown address family in peer->Remote", TraceLoggingValue(peer->Remote.Addr4.sin_family, "AF"));
        goto done;
    }

    // allocate peer
    peerCtx = OvpnPeerCtxAlloc();
    if (peerCtx == NULL) {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    // assign remote transport address
    auto ipv4 = peer->Remote.Addr4.sin_family == AF_INET;
    if (ipv4) {
        peerCtx->TransportAddrs.Remote.IPv4 = peer->Remote.Addr4;
    }
    else {
        peerCtx->TransportAddrs.Remote.IPv6 = peer->Remote.Addr6;
    }

    peerCtx->VpnAddrs.IPv4 = peer->VpnAddr4;
    peerCtx->VpnAddrs.IPv6 = peer->VpnAddr6;

    peerCtx->PeerId = peer->PeerId;

    // create peer-specific timer
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerCreate(device->WdfDevice, peerCtx, &peerCtx->Timer));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnAddPeerToTable(device, &device->Peers, peerCtx));
    
    if (peer->VpnAddr4.S_un.S_addr != INADDR_ANY) {
        LOG_IF_NOT_NT_SUCCESS(status = OvpnAddPeerToTable(device, &device->PeersByVpn4, peerCtx));
    }

    if (RtlCompareMemory(&peer->VpnAddr6, &ovpn_in6addr_any, sizeof(IN6_ADDR)) != sizeof(IN6_ADDR)) {
        LOG_IF_NOT_NT_SUCCESS(status = OvpnAddPeerToTable(device, &device->PeersByVpn6, peerCtx));
    }

    LOG_IF_NOT_NT_SUCCESS(status = OvpnAddPeerToTable(device, &device->PeersByTransport, peerCtx));

    if (ipv4) {
        LOG_INFO("Peer added", TraceLoggingValue(peer->PeerId, "peer-id"),
            TraceLoggingIPv4Address(peer->Remote.Addr4.sin_addr.S_un.S_addr, "IPv4"),
            TraceLoggingIPv4Address(peer->VpnAddr4.S_un.S_addr, "VPN IPv4"),
            TraceLoggingIPv6Address(&peer->VpnAddr6, "VPN IPv6"));
    }
    else {
        LOG_INFO("Peer added", TraceLoggingValue(peer->PeerId, "peer-id"),
            TraceLoggingIPv6Address(&peer->Remote.Addr6.sin6_addr, "IPv6"),
            TraceLoggingIPv4Address(peer->VpnAddr4.S_un.S_addr, "VPN IPv4"),
            TraceLoggingIPv6Address(&peer->VpnAddr6, "VPN IPv6"));
    }

done:
    if (peerCtx != nullptr) {
        OvpnPeerCtxRelease(peerCtx);
    }

    LOG_EXIT();

    return status;
}

VOID OvpnPeerSetDoWork(OvpnPeerContext *peer, LONG keepaliveInterval, LONG keepaliveTimeout, LONG mss)
{
    auto irql = ExAcquireSpinLockExclusive(&peer->SpinLock);

    if (mss != -1) {
        peer->MSS = (UINT16)mss;
    }

    if (keepaliveInterval != -1) {
        peer->KeepaliveInterval = keepaliveInterval;

        // keepalive xmit timer, sends ping packets
        OvpnTimerSetXmitInterval(peer->Timer, peer->KeepaliveInterval);
    }

    if (keepaliveTimeout != -1) {
        peer->KeepaliveTimeout = keepaliveTimeout;

        // keepalive recv timer, detects keepalive timeout
        OvpnTimerSetRecvTimeout(peer->Timer, peer->KeepaliveTimeout);
    }

    ExReleaseSpinLockExclusive(&peer->SpinLock, irql);
}

_Use_decl_annotations_
NTSTATUS OvpnPeerSet(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    OvpnPeerContext* peer = OvpnGetFirstPeer(device);
    if (peer == nullptr) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    POVPN_SET_PEER set_peer = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_SET_PEER), (PVOID*)&set_peer, nullptr));

    LOG_INFO("Set peer", TraceLoggingValue(set_peer->KeepaliveInterval, "interval"),
        TraceLoggingValue(set_peer->KeepaliveTimeout, "timeout"),
        TraceLoggingValue(set_peer->MSS, "MSS"));

    OvpnPeerSetDoWork(peer, set_peer->KeepaliveInterval, set_peer->KeepaliveTimeout, set_peer->MSS);

done:
    if (peer != nullptr) {
        OvpnPeerCtxRelease(peer);
    }

    LOG_EXIT();
    return status;
}

_Use_decl_annotations_
NTSTATUS OvpnMPPeerSet(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    OvpnPeerContext* peer = nullptr;

    POVPN_MP_SET_PEER set_peer = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_MP_SET_PEER), (PVOID*)&set_peer, nullptr));

    LOG_INFO("MP Set peer", TraceLoggingValue(set_peer->PeerId, "peer-id"),
        TraceLoggingValue(set_peer->KeepaliveInterval, "interval"),
        TraceLoggingValue(set_peer->KeepaliveTimeout, "timeout"),
        TraceLoggingValue(set_peer->MSS, "MSS"));

    peer = OvpnFindPeer(device, set_peer->PeerId, FALSE);
    if (peer == nullptr) {
        LOG_ERROR("Peer not found", TraceLoggingValue(set_peer->PeerId, "peer-id"));
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    OvpnPeerSetDoWork(peer, set_peer->KeepaliveInterval, set_peer->KeepaliveTimeout, set_peer->MSS);

done:
    if (peer != nullptr) {
        OvpnPeerCtxRelease(peer);
    }

    LOG_EXIT();
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerGetStats(POVPN_DEVICE device, WDFREQUEST request, ULONG_PTR* bytesReturned)
{
    NTSTATUS status = STATUS_SUCCESS;

    POVPN_STATS stats = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveOutputBuffer(request, sizeof(OVPN_STATS), (PVOID*)&stats, NULL));

    stats->LostInControlPackets = InterlockedCompareExchangeNoFence(&device->Stats.LostInControlPackets, 0, 0);
    stats->LostInDataPackets = InterlockedCompareExchangeNoFence(&device->Stats.LostInDataPackets, 0, 0);
    stats->LostOutControlPackets = InterlockedCompareExchangeNoFence(&device->Stats.LostOutControlPackets, 0, 0);
    stats->LostOutDataPackets = InterlockedCompareExchangeNoFence(&device->Stats.LostOutDataPackets, 0, 0);
    stats->ReceivedControlPackets = InterlockedCompareExchangeNoFence(&device->Stats.ReceivedControlPackets, 0, 0);
    stats->ReceivedDataPackets = InterlockedCompareExchangeNoFence(&device->Stats.ReceivedDataPackets, 0, 0);
    stats->SentControlPackets = InterlockedCompareExchangeNoFence(&device->Stats.SentControlPackets, 0, 0);
    stats->SentDataPackets = InterlockedCompareExchangeNoFence(&device->Stats.SentDataPackets, 0, 0);
    stats->TransportBytesReceived = InterlockedCompareExchangeNoFence64(&device->Stats.TransportBytesReceived, 0, 0);
    stats->TransportBytesSent = InterlockedCompareExchangeNoFence64(&device->Stats.TransportBytesSent, 0, 0);
    stats->TunBytesReceived = InterlockedCompareExchangeNoFence64(&device->Stats.TunBytesReceived, 0, 0);
    stats->TunBytesSent = InterlockedCompareExchangeNoFence64(&device->Stats.TunBytesSent, 0, 0);

    *bytesReturned = sizeof(OVPN_STATS);

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerGetStatsV2(POVPN_DEVICE device, WDFREQUEST request, ULONG_PTR* bytesReturned)
{
    *bytesReturned = 0;

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_GET_PEER_STATS getPeerStats = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_GET_PEER_STATS), (PVOID*)&getPeerStats, nullptr));

    POVPN_PEER_STATS outBuf = NULL;

    // requested stats for all peers?
    if (getPeerStats->PeerId == -1) {
        // Ensure the output buffer is at least large enough to hold the required size
        size_t bufferSize;
        LOG_IF_NOT_NT_SUCCESS(status = WdfRequestRetrieveOutputBuffer(request, sizeof(ULONG), (PVOID*)&outBuf, &bufferSize));
        if (!NT_SUCCESS(status)) {
            goto done;
        }

        auto irql = ExAcquireSpinLockExclusive(&device->SpinLock);
        ULONG peerNum = RtlNumberGenericTableElements(&device->Peers);

        // no peers?
        if (peerNum == 0) {
            ExReleaseSpinLockExclusive(&device->SpinLock, irql);
            goto done;
        }

        size_t requiredSize = peerNum * sizeof(OVPN_PEER_STATS);

        // if buffer is too small for the whole data, return the required size
        if (bufferSize < requiredSize) {
            *(ULONG*)outBuf = (ULONG)requiredSize;

            // this is the only working way to return required buffer size to the userspace
            // https://community.osr.com/t/returning-data-when-completing-with-wdfrequestcompletewithinformation-fails/58284/3
            status = STATUS_BUFFER_OVERFLOW;
            *bytesReturned = sizeof(ULONG);
            ExReleaseSpinLockExclusive(&device->SpinLock, irql);
            goto done;
        }

        PVOID restartKey = NULL;
        PVOID ptr;
        int i = 0;
        while ((ptr = RtlEnumerateGenericTableWithoutSplaying(&device->Peers, &restartKey)) != NULL) {
            OvpnPeerContext* peer = *(OvpnPeerContext**)ptr;
            outBuf[i].PeerId = peer->PeerId;
            outBuf[i].LinkRxBytes = peer->LinkRxBytes;
            outBuf[i].LinkTxBytes = peer->LinkTxBytes;
            outBuf[i].VpnRxBytes = peer->VpnRxBytes;
            outBuf[i].VpnTxBytes = peer->VpnTxBytes;
            ++i;
        }

        ExReleaseSpinLockExclusive(&device->SpinLock, irql);

        *bytesReturned = requiredSize;
    }
    else {
        // return stats for the single peer

        LOG_IF_NOT_NT_SUCCESS(status = WdfRequestRetrieveOutputBuffer(request, sizeof(OVPN_PEER_STATS), (PVOID*)&outBuf, nullptr));
        if (!NT_SUCCESS(status)) {
            goto done;
        }

        OvpnPeerContext *peer = OvpnFindPeer(device, getPeerStats->PeerId, FALSE);
        if (peer == nullptr) {
            status = STATUS_OBJECTID_NOT_FOUND;
            goto done;
        }

        outBuf->PeerId = peer->PeerId;
        outBuf->LinkRxBytes = peer->LinkRxBytes;
        outBuf->LinkTxBytes = peer->LinkTxBytes;
        outBuf->VpnRxBytes = peer->VpnRxBytes;
        outBuf->VpnTxBytes = peer->VpnTxBytes;

        OvpnPeerCtxRelease(peer);

        *bytesReturned = sizeof(OVPN_PEER_STATS);
    }

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerStartVPN(POVPN_DEVICE device)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    auto peer = OvpnGetFirstPeer(device);
    if (peer == nullptr) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    OvpnAdapterSetLinkState(OvpnGetAdapterContext(device->Adapter), MediaConnectStateConnected);

done:
    if (peer != nullptr) {
        OvpnPeerCtxRelease(peer);
    }

    LOG_EXIT();

    return status;
}

static NTSTATUS
OvpnPeerGetAlgHandle(POVPN_DEVICE device, OVPN_CIPHER_ALG cipherAlg, BCRYPT_ALG_HANDLE& algHandle)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (cipherAlg) {
    case OVPN_CIPHER_ALG_AES_GCM:
        algHandle = device->AesAlgHandle;
        break;

    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
        algHandle = device->ChachaAlgHandle;
        if (algHandle == NULL) {
            LOG_ERROR("CHACHA20-POLY1305 is not available");
            status = STATUS_INVALID_DEVICE_REQUEST;
        }
        break;

    default:
        break;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerNewKey(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_CRYPTO_DATA cryptoData = NULL;
    OVPN_CRYPTO_DATA_V2 cryptoDataV2{};
    OvpnPeerContext* peer = nullptr;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA), (PVOID*)&cryptoData, nullptr));

    BCRYPT_ALG_HANDLE algHandle = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPeerGetAlgHandle(device, cryptoData->CipherAlg, algHandle));

    peer = OvpnFindPeer(device, cryptoData->PeerId, FALSE);
    if (peer == nullptr) {
        status = STATUS_OBJECTID_NOT_FOUND;
        goto done;
    }

    RtlCopyMemory(&cryptoDataV2.V1, cryptoData, sizeof(OVPN_CRYPTO_DATA));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoNewKey(&peer->CryptoContext, &cryptoDataV2, algHandle));

done:
    if (peer != nullptr) {
        OvpnPeerCtxRelease(peer);
    }

    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerNewKeyV2(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;
    OvpnPeerContext* peer = nullptr;

    POVPN_CRYPTO_DATA_V2 cryptoDataV2 = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA_V2), (PVOID*)&cryptoDataV2, nullptr));

    BCRYPT_ALG_HANDLE algHandle = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPeerGetAlgHandle(device, cryptoDataV2->V1.CipherAlg, algHandle));

    peer = OvpnFindPeer(device, cryptoDataV2->V1.PeerId, FALSE);

    if (peer == nullptr) {
        status = STATUS_OBJECTID_NOT_FOUND;
        goto done;
    }

    KIRQL irql = ExAcquireSpinLockExclusive(&peer->SpinLock);
    LOG_IF_NOT_NT_SUCCESS(status = OvpnCryptoNewKey(&peer->CryptoContext, cryptoDataV2, algHandle));
    ExReleaseSpinLockExclusive(&peer->SpinLock, irql);

done:
    if (peer != nullptr) {
        OvpnPeerCtxRelease(peer);
    }

    LOG_EXIT();

    return status;
}

NTSTATUS
OvpnPeerDoSwapKeys(POVPN_DEVICE device, INT32 peerId)
{
    LOG_INFO("Swap Keys", TraceLoggingValue(peerId, "peer-id"));

    // in client mode this returns the only peer
    OvpnPeerContext* peer = OvpnFindPeer(device, peerId, FALSE);
    if (peer != nullptr) {
        KIRQL irql = ExAcquireSpinLockExclusive(&peer->SpinLock);
        OvpnCryptoSwapKeys(&peer->CryptoContext);
        ExReleaseSpinLockExclusive(&peer->SpinLock, irql);

        OvpnPeerCtxRelease(peer);

        return STATUS_SUCCESS;
    }
    else {
        LOG_ERROR("Peer not found");
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerSwapKeys(POVPN_DEVICE device)
{
    // in client mode peer-id doesn't matter
    return OvpnPeerDoSwapKeys(device, 0);
}

PCCH
OvpnPeerGetDelReasonString(OVPN_DEL_PEER_REASON reason) {
    switch (reason) {
    case OVPN_DEL_PEER_REASON_TEARDOWN:
        return "Teardown";
    case OVPN_DEL_PEER_REASON_USERSPACE:
        return "Userspace";
    case OVPN_DEL_PEER_REASON_EXPIRED:
        return "Expired";
    case OVPN_DEL_PEER_REASON_TRANSPORT_ERROR:
        return "Transport Error";
    case OVPN_DEL_PEER_REASON_TRANSPORT_DISCONNECT:
        return "Transport Disconnect";
    default:
        return "Unknown Reason";
    }
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerDelete(POVPN_DEVICE device, INT32 peerId, OVPN_DEL_PEER_REASON reason, BOOLEAN notify)
{
    NTSTATUS status = STATUS_SUCCESS;

    LOG_INFO("Deleting peer", TraceLoggingValue(peerId, "peer-id"), TraceLoggingValue(OvpnPeerGetDelReasonString(reason), "reason"));

    // get peer from main table
    OvpnPeerContext* peer = OvpnFindPeer(device, peerId, FALSE);
    if (peer != nullptr) {
        OvpnDeletePeerFromTable(device, &device->PeersByTransport, peer, "transport");
        OvpnDeletePeerFromTable(device, &device->PeersByVpn4, peer, "vpn4");
        OvpnDeletePeerFromTable(device, &device->PeersByVpn6, peer, "vpn6");
        OvpnDeletePeerFromTable(device, &device->Peers, peer, "peers");

        device->IRoutesIPV4.RemoveByPeerId(peer->PeerId);
        device->IRoutesIPV6.RemoveByPeerId(peer->PeerId);

        OvpnPeerCtxRelease(peer);

        // notify userspace
        if (notify) {
            OvpnDeviceNotifyPeerDel(device, peerId, reason);
        }
    } else {
        status = STATUS_NOT_FOUND;
        LOG_WARN("Peer not found", TraceLoggingValue(peerId, "peer-id"));
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnMPPeerDelete(POVPN_DEVICE device, WDFREQUEST request)
{
    NTSTATUS status = STATUS_SUCCESS;

    LOG_ENTER();

    POVPN_MP_DEL_PEER del_peer = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_MP_DEL_PEER), (PVOID*)&del_peer, nullptr));

    LOG_IF_NOT_NT_SUCCESS(status = OvpnPeerDelete(device, del_peer->PeerId, OVPN_DEL_PEER_REASON_USERSPACE, TRUE));

done:
    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnMPPeerSwapKeys(POVPN_DEVICE device, WDFREQUEST request)
{
    NTSTATUS status = STATUS_SUCCESS;

    POVPN_MP_SWAP_KEYS swap_keys = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_MP_SWAP_KEYS), (PVOID*)&swap_keys, nullptr));

    LOG_IF_NOT_NT_SUCCESS(status = OvpnPeerDoSwapKeys(device, swap_keys->PeerId));

done:
    return status;
}

NTSTATUS
OvpnPeerHandleFloat(OVPN_DEVICE* device, OvpnPeerContext *peer, PSOCKADDR sa, BOOLEAN dpc)
{
    OvpnPeerContext* lookup_peer = OvpnFindPeerTransport(device, sa, dpc);

    // no float?
    if (lookup_peer == peer) {
        OvpnPeerCtxRelease(lookup_peer);
        return STATUS_SUCCESS;
    }

    // deny float to a taken address
    if (lookup_peer != nullptr) {
        if (sa->sa_family == AF_INET)
            LOG_INFO("Deny float to a taken address", TraceLoggingValue(peer->PeerId, "peer-id-src"),
                TraceLoggingValue(lookup_peer->PeerId, "peer-id-dst"),
                TraceLoggingIPv4Address(peer->TransportAddrs.Remote.IPv4.sin_addr.S_un.S_addr, "src"),
                TraceLoggingIPv4Address(((SOCKADDR_IN*)sa)->sin_addr.S_un.S_addr, "dst"));
        else
            LOG_INFO("Deny float to a taken address", TraceLoggingValue(peer->PeerId, "peer-id-src"),
                TraceLoggingValue(lookup_peer->PeerId, "peer-id-dst"),
                TraceLoggingIPv6Address(&peer->TransportAddrs.Remote.IPv6.sin6_addr, "src"),
                TraceLoggingIPv6Address(&((SOCKADDR_IN6*)sa)->sin6_addr, "dst"));

        OvpnPeerCtxRelease(lookup_peer);

        return STATUS_ADDRESS_ALREADY_EXISTS;
    }

    // commit float

    if (sa->sa_family == AF_INET)
        LOG_INFO("Peer floated", TraceLoggingValue(peer->PeerId, "peer-id"),
            TraceLoggingIPv4Address(peer->TransportAddrs.Remote.IPv4.sin_addr.S_un.S_addr, "src"),
            TraceLoggingIPv4Address(((SOCKADDR_IN*)sa)->sin_addr.S_un.S_addr, "dst"));
    else
        LOG_INFO("Peer floated", TraceLoggingValue(peer->PeerId, "peer-id"),
            TraceLoggingIPv6Address(&peer->TransportAddrs.Remote.IPv6.sin6_addr, "src"),
            TraceLoggingIPv6Address(&((SOCKADDR_IN6*)sa)->sin6_addr, "dst"));

    KIRQL kirql = 0;

    // remove peer from by-transport-address hashtable
    OvpnDeletePeerFromTable(device, &device->PeersByTransport, peer, "transport");

    // modify peer's transport address
    {
        // exclusive-lock peer
        if (dpc) {
            ExAcquireSpinLockExclusiveAtDpcLevel(&peer->SpinLock);
        }
        else {
            kirql = ExAcquireSpinLockExclusive(&peer->SpinLock);
        }

        // update peer's transport address
        if (sa->sa_family == AF_INET)
            RtlCopyMemory(&peer->TransportAddrs.Remote.IPv4, sa, sizeof(SOCKADDR_IN));
        else
            RtlCopyMemory(&peer->TransportAddrs.Remote.IPv6, sa, sizeof(SOCKADDR_IN6));

        // exclusive-unlock peer
        if (dpc) {
            ExReleaseSpinLockExclusiveFromDpcLevel(&peer->SpinLock);
        }
        else {
            ExReleaseSpinLockExclusive(&peer->SpinLock, kirql);
        }
    }

    // add peer back to by-transport-address hashtable
    LOG_IF_NOT_NT_SUCCESS(OvpnAddPeerToTable(device, &device->PeersByTransport, peer));

    LOG_IF_NOT_NT_SUCCESS(OvpnDeviceNotifyPeerFloat(device, peer->PeerId, sa));

    return STATUS_SUCCESS;
}
