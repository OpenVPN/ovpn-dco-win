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
    OvpnTimerDestroy(&peer->KeepaliveXmitTimer);
    OvpnTimerDestroy(&peer->KeepaliveRecvTimer);

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

RTL_GENERIC_COMPARE_RESULTS OvpnPeerCompareByPeerIdRoutine(_RTL_GENERIC_TABLE* table, PVOID first, PVOID second)
{
    UNREFERENCED_PARAMETER(table);
    UNREFERENCED_PARAMETER(first);
    UNREFERENCED_PARAMETER(second);

    return GenericEqual;
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
OvpnPeerDel(POVPN_DEVICE device)
{
    LOG_ENTER();

    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);

    PWSK_SOCKET socket = device->Socket.Socket;

    device->Socket.Socket = NULL;
    OvpnFlushPeers(device);

    RtlZeroMemory(&device->Socket.TcpState, sizeof(OvpnSocketTcpState));
    RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));

    // OvpnSocketClose requires PASSIVE_LEVEL, so must release lock
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

    LOG_IF_NOT_NT_SUCCESS(OvpnSocketClose(socket));

    // flush buffers in control queue so that client won't get control channel messages from previous session
    while (LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->ControlRxBufferQueue)) {
        OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(entry, OVPN_RX_BUFFER, QueueListEntry);
        // return buffer back to pool
        OvpnRxBufferPoolPut(buffer);
    }

    WDFREQUEST request;
    while (NT_SUCCESS(WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request))) {
        ULONG_PTR bytesCopied = 0;
        LOG_INFO("Cancel IO request from manual queue");
        WdfRequestCompleteWithInformation(request, STATUS_CANCELLED, bytesCopied);
    }

    LOG_EXIT();

    return STATUS_SUCCESS;
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

        if (peer->KeepaliveInterval > 0) {
            // keepalive xmit timer, sends ping packets
            GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerXmitCreate(device->WdfDevice, peer, peer->KeepaliveInterval, &peer->KeepaliveXmitTimer));
            OvpnTimerReset(peer->KeepaliveXmitTimer, peer->KeepaliveInterval);
        }
        else {
            LOG_INFO("Destroy xmit timer");
            OvpnTimerDestroy(&peer->KeepaliveXmitTimer);
        }
    }

    if (peer->KeepaliveTimeout != -1) {
        peer->KeepaliveTimeout = set_peer->KeepaliveTimeout;

        if (peer->KeepaliveTimeout > 0) {
            // keepalive recv timer, detects keepalive timeout
            GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerRecvCreate(device->WdfDevice, peer, &peer->KeepaliveRecvTimer));
            OvpnTimerReset(peer->KeepaliveRecvTimer, peer->KeepaliveTimeout);
        }
        else {
            LOG_INFO("Destroy recv timer");
            OvpnTimerDestroy(&peer->KeepaliveRecvTimer);
        }
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

_Use_decl_annotations_
NTSTATUS
OvpnPeerNewKey(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    if (!OvpnHasPeers(device)) {
        LOG_ERROR("Peer not added");
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    POVPN_CRYPTO_DATA cryptoData = NULL;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA), (PVOID*)&cryptoData, nullptr));

    BCRYPT_ALG_HANDLE algHandle = NULL;
    switch (cryptoData->CipherAlg) {
    case OVPN_CIPHER_ALG_AES_GCM:
        algHandle = device->AesAlgHandle;
        device->CryptoOverhead = AEAD_CRYPTO_OVERHEAD;
        break;

    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
        algHandle = device->ChachaAlgHandle;
        if (algHandle == NULL) {
            LOG_ERROR("CHACHA20-POLY1305 is not available");
            status = STATUS_INVALID_DEVICE_REQUEST;
            goto done;
        }
        device->CryptoOverhead = AEAD_CRYPTO_OVERHEAD;

    default:
        device->CryptoOverhead = NONE_CRYPTO_OVERHEAD;
        break;
    }

    OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);
    if (peer == NULL) {
        status = STATUS_OBJECTID_NOT_FOUND;
        goto done;
    }

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoNewKey(&peer->CryptoContext, cryptoData, algHandle));

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

