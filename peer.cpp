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
    }
    return peer;
}

_Use_decl_annotations_
VOID
OvpnPeerCtxFree(OvpnPeerContext* peer)
{
    OvpnCryptoUninit(&peer->CryptoContext);
    OvpnTimerDestroy(&peer->Timer);

    ExFreePoolWithTag(peer, 'ovpn');
}

_Use_decl_annotations_
PVOID
OvpnPeerAllocateRoutine(_RTL_GENERIC_TABLE* table, CLONG size)
{
    UNREFERENCED_PARAMETER(table);

    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'ovpn');
}

_Use_decl_annotations_
VOID
OvpnPeerFreeRoutine(_RTL_GENERIC_TABLE* table, PVOID buffer)
{
    UNREFERENCED_PARAMETER(table);

    ExFreePoolWithTag(buffer, 'ovpn');
}

RTL_GENERIC_COMPARE_RESULTS
OvpnPeerCompareByPeerIdRoutine(_RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
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
OvpnPeerCompareByVPN4Routine(_RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
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
OvpnPeerCompareByVPN6Routine(_RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
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
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_NEW_PEER), (PVOID*)&peer, nullptr));

    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
    const BOOLEAN peerExists = OvpnHasPeers(device);
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
    if (peerExists) {
        LOG_WARN("Peer already exists");
        status = STATUS_OBJECTID_EXISTS;
        goto done;
    }

    POVPN_DRIVER driver = OvpnGetDriverContext(WdfGetDriver());
    PWSK_SOCKET socket = NULL;
    BOOLEAN proto_tcp = peer->Proto == OVPN_PROTO_TCP;
    SIZE_T remoteAddrSize = peer->Remote.Addr4.sin_family == AF_INET ? sizeof(peer->Remote.Addr4) : sizeof(peer->Remote.Addr6);

    OvpnPeerContext* peerCtx = OvpnPeerCtxAlloc();
    if (peerCtx == NULL) {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnSocketInit(&driver->WskProviderNpi,
        &driver->WskRegistration, peer->Local.Addr4.sin_family, proto_tcp,
        (PSOCKADDR)&peer->Local,
        (PSOCKADDR)&peer->Remote,
        remoteAddrSize, device, &socket));

    kirql = ExAcquireSpinLockExclusive(&device->SpinLock);

    LOG_IF_NOT_NT_SUCCESS(status = OvpnAddPeer(device, peerCtx));
    if (status != STATUS_SUCCESS) {
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        OvpnPeerCtxFree(peerCtx);
        LOG_IF_NOT_NT_SUCCESS(OvpnSocketClose(socket));
    }
    else {
        device->Socket.Socket = socket;
        device->Socket.Tcp = proto_tcp;
        RtlZeroMemory(&device->Socket.TcpState, sizeof(OvpnSocketTcpState));
        RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

        OvpnPeerZeroStats(&device->Stats);

        GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerCreate(device->WdfDevice, peerCtx, &peerCtx->Timer));

        if (proto_tcp) {
            LOG_IF_NOT_NT_SUCCESS(status = WdfRequestForwardToIoQueue(request, device->PendingNewPeerQueue));
            // start async connect
            status = OvpnSocketTcpConnect(socket, device, (PSOCKADDR)&peer->Remote);
        }
    }

done:
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

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_MP_NEW_PEER), (PVOID*)&peer, nullptr));

    // check if we already have a peer with the same peer-id
    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
    OvpnPeerContext* peerCtx = OvpnFindPeer(device, peer->PeerId);
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
    if (peerCtx != NULL) {
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

    // assign local transport address
    if (peer->Local.Addr4.sin_family == AF_INET) {
        peerCtx->TransportAddrs.Local.IPv4 = peer->Local.Addr4.sin_addr;
    }
    else {
        peerCtx->TransportAddrs.Local.IPv6 = peer->Local.Addr6.sin6_addr;
    }

    // assign remote transport address
    if (peer->Remote.Addr4.sin_family == AF_INET) {
        peerCtx->TransportAddrs.Remote.IPv4 = peer->Remote.Addr4;
    }
    else {
        peerCtx->TransportAddrs.Remote.IPv6 = peer->Remote.Addr6;
    }

    peerCtx->VpnAddrs.IPv4 = peer->VpnAddr4;
    peerCtx->VpnAddrs.IPv6 = peer->VpnAddr6;

    peerCtx->PeerId = peer->PeerId;

    kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
    LOG_IF_NOT_NT_SUCCESS(status = OvpnAddPeer(device, peerCtx));
    if (status == STATUS_SUCCESS) {
        if (peer->VpnAddr4.S_un.S_addr != INADDR_ANY) {
            LOG_IF_NOT_NT_SUCCESS(status = OvpnAddPeerVpn4(device, peerCtx));
        }

        if (RtlCompareMemory(&peer->VpnAddr6, &ovpn_in6addr_any, sizeof(IN6_ADDR)) != sizeof(IN6_ADDR)) {
            LOG_IF_NOT_NT_SUCCESS(status = OvpnAddPeerVpn6(device, peerCtx));
        }
    }
    else {
        OvpnPeerCtxFree(peerCtx);
    }
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

done:
    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS OvpnPeerSet(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);

    if (peer == NULL) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    POVPN_SET_PEER set_peer = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_SET_PEER), (PVOID*)&set_peer, nullptr));

    LOG_INFO("Set peer", TraceLoggingValue(set_peer->KeepaliveInterval, "interval"),
        TraceLoggingValue(set_peer->KeepaliveTimeout, "timeout"),
        TraceLoggingValue(set_peer->MSS, "MSS"));

    if (set_peer->MSS != -1) {
        device->MSS = (UINT16)set_peer->MSS;
    }

    if (set_peer->KeepaliveInterval != -1) {
        peer->KeepaliveInterval = set_peer->KeepaliveInterval;

        // keepalive xmit timer, sends ping packets
        OvpnTimerSetXmitInterval(peer->Timer, peer->KeepaliveInterval);
    }

    if (peer->KeepaliveTimeout != -1) {
        peer->KeepaliveTimeout = set_peer->KeepaliveTimeout;

        // keepalive recv timer, detects keepalive timeout
        OvpnTimerSetRecvTimeout(peer->Timer, peer->KeepaliveTimeout);
    }

done:
    LOG_EXIT();
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerGetStats(POVPN_DEVICE device, WDFREQUEST request, ULONG_PTR* bytesReturned)
{
    NTSTATUS status = STATUS_SUCCESS;

    OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);
    if (peer == NULL) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

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
OvpnPeerStartVPN(POVPN_DEVICE device)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    if (!OvpnHasPeers(device)) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    OvpnAdapterSetLinkState(OvpnGetAdapterContext(device->Adapter), MediaConnectStateConnected);

done:
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

    if (!OvpnHasPeers(device)) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA), (PVOID*)&cryptoData, nullptr));

    BCRYPT_ALG_HANDLE algHandle = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPeerGetAlgHandle(device, cryptoData->CipherAlg, algHandle));

    OvpnPeerContext* peer = OvpnFindPeer(device, cryptoData->PeerId);
    if (peer == NULL) {
        status = STATUS_OBJECTID_NOT_FOUND;
        goto done;
    }

    RtlCopyMemory(&cryptoDataV2.V1, cryptoData, sizeof(OVPN_CRYPTO_DATA));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoNewKey(&peer->CryptoContext, &cryptoDataV2, algHandle));

done:
    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerNewKeyV2(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_CRYPTO_DATA_V2 cryptoDataV2 = NULL;

    if (!OvpnHasPeers(device)) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA_V2), (PVOID*)&cryptoDataV2, nullptr));

    BCRYPT_ALG_HANDLE algHandle = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPeerGetAlgHandle(device, cryptoDataV2->V1.CipherAlg, algHandle));

    OvpnPeerContext* peer = OvpnFindPeer(device, cryptoDataV2->V1.PeerId);
    if (peer == NULL) {
        status = STATUS_OBJECTID_NOT_FOUND;
        goto done;
    }

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoNewKey(&peer->CryptoContext, cryptoDataV2, algHandle));

done:
    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerSwapKeys(POVPN_DEVICE device)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    if (!OvpnHasPeers(device)) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);
    if (peer == NULL) {
        LOG_ERROR("Peer not found");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    OvpnCryptoSwapKeys(&peer->CryptoContext);

done:
    LOG_EXIT();

    return status;
}

