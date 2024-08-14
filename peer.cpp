/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
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

    ULONG newPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(request));
    LONG existingPid = InterlockedCompareExchange(&device->UserspacePid, 0, 0);

    if (existingPid != 0) {
        LOG_INFO("Peer already added, deleting existing peer");
        LOG_IF_NOT_NT_SUCCESS(OvpnPeerDel(device));
    }

    InterlockedExchange(&device->UserspacePid, newPid);

    LOG_INFO("Userspace client connected", TraceLoggingValue(newPid, "pid"));

    POVPN_DRIVER driver = OvpnGetDriverContext(WdfGetDriver());
    PWSK_SOCKET socket = NULL;
    BOOLEAN proto_tcp = peer->Proto == OVPN_PROTO_TCP;
    SIZE_T remoteAddrSize = peer->Remote.Addr4.sin_family == AF_INET ? sizeof(peer->Remote.Addr4) : sizeof(peer->Remote.Addr6);

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnSocketInit(&driver->WskProviderNpi, &driver->WskRegistration, peer->Local.Addr4.sin_family, proto_tcp, (PSOCKADDR)&peer->Local,
        (PSOCKADDR)&peer->Remote, remoteAddrSize, device, &socket));

    BCRYPT_ALG_HANDLE aesAlgHandle = NULL, chachaAlgHandle = NULL;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoInitAlgHandles(&aesAlgHandle, &chachaAlgHandle));

    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
    RtlZeroMemory(&device->CryptoContext, sizeof(OvpnCryptoContext));
    device->CryptoContext.AesAlgHandle = aesAlgHandle;
    device->CryptoContext.ChachaAlgHandle = chachaAlgHandle;
    device->Socket.Socket = socket;
    device->Socket.Tcp = proto_tcp;
    RtlZeroMemory(&device->Socket.TcpState, sizeof(OvpnSocketTcpState));
    RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

    OvpnPeerZeroStats(&device->Stats);

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerCreate(device->WdfDevice, &device->Timer));

    if (proto_tcp) {
        LOG_IF_NOT_NT_SUCCESS(status = WdfRequestForwardToIoQueue(request, device->PendingNewPeerQueue));
        // start async connect
        LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketTcpConnect(socket, device, (PSOCKADDR)&peer->Remote));
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

    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_INFO("Peer not added.");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    BCRYPT_ALG_HANDLE aesAlgHandle = NULL, chachaAlgHandle = NULL;

    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);

    OvpnTimerDestroy(&device->Timer);

    aesAlgHandle = device->CryptoContext.AesAlgHandle;
    chachaAlgHandle = device->CryptoContext.ChachaAlgHandle;

    OvpnCryptoUninit(&device->CryptoContext);

    InterlockedExchange(&device->UserspacePid, 0);

    PWSK_SOCKET socket = device->Socket.Socket;
    device->Socket.Socket = NULL;

    RtlZeroMemory(&device->Socket.TcpState, sizeof(OvpnSocketTcpState));
    RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));

    // OvpnCryptoUninitAlgHandles and OvpnSocketClose require PASSIVE_LEVEL, so must release lock
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

    OvpnCryptoUninitAlgHandles(aesAlgHandle, chachaAlgHandle);

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

    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    POVPN_SET_PEER peer = NULL;
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_SET_PEER), (PVOID*)&peer, nullptr));

    LOG_INFO("Set peer", TraceLoggingValue(peer->KeepaliveInterval, "interval"),
        TraceLoggingValue(peer->KeepaliveTimeout, "timeout"),
        TraceLoggingValue(peer->MSS, "MSS"));

    if (peer->MSS != -1) {
        device->MSS = (UINT16)peer->MSS;
    }

    if (peer->KeepaliveInterval != -1) {
        device->KeepaliveInterval = peer->KeepaliveInterval;

        // keepalive xmit timer, sends ping packets
        OvpnTimerSetXmitInterval(device->Timer, peer->KeepaliveInterval);
    }

    if (peer->KeepaliveTimeout != -1) {
        device->KeepaliveTimeout = peer->KeepaliveTimeout;

        // keepalive recv timer, detects keepalive timeout
        OvpnTimerSetRecvTimeout(device->Timer, peer->KeepaliveTimeout);
    }

done:
    LOG_EXIT();
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerGetStats(POVPN_DEVICE device, WDFREQUEST request, ULONG_PTR* bytesReturned)
{
    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    POVPN_STATS stats = NULL;
    NTSTATUS status;
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

    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    OvpnAdapterSetLinkState(OvpnGetAdapterContext(device->Adapter), MediaConnectStateConnected);

    LOG_EXIT();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerNewKey(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    POVPN_CRYPTO_DATA cryptoData = NULL;
    OVPN_CRYPTO_DATA_V2 cryptoDataV2{};
    NTSTATUS status;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA), (PVOID*)&cryptoData, nullptr));

    RtlCopyMemory(&cryptoDataV2.V1, cryptoData, sizeof(OVPN_CRYPTO_DATA));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoNewKey(&device->CryptoContext, &cryptoDataV2));

done:
    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerNewKeyV2(POVPN_DEVICE device, WDFREQUEST request)
{
    LOG_ENTER();

    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    POVPN_CRYPTO_DATA_V2 cryptoData = NULL;
    NTSTATUS status;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA_V2), (PVOID*)&cryptoData, nullptr));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoNewKey(&device->CryptoContext, cryptoData));

done:
    LOG_EXIT();

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerSwapKeys(POVPN_DEVICE device)
{
    LOG_ENTER();

    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    OvpnCryptoSwapKeys(&device->CryptoContext);

    LOG_EXIT();

    return STATUS_SUCCESS;
}
