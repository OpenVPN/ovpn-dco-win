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

    OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);
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

    OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);
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

