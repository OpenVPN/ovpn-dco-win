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
    POVPN_NEW_PEER peer = NULL;
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_NEW_PEER), (PVOID*)&peer, nullptr));

    ULONG newPid = IoGetRequestorProcessId(WdfRequestWdmGetIrp(request));
    LONG existingPid = InterlockedCompareExchange(&device->UserspacePid, 0, 0);

    if (existingPid != 0) {
        LOG_ERROR("Peer already added by client pid <pid1>, denying request from client pid <pid2>", TraceLoggingValue(existingPid, "pid1"), TraceLoggingValue(newPid, "pid2"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    InterlockedExchange(&device->UserspacePid, newPid);

    LOG_INFO("Userspace client connected", TraceLoggingValue(newPid, "pid"));

    POVPN_DRIVER driver = OvpnGetDriverContext(WdfGetDriver());
    PWSK_SOCKET socket = NULL;
    BOOLEAN proto_tcp = peer->Proto == OVPN_PROTO_TCP;
    SIZE_T remoteAddrSize = peer->Remote.Addr4.sin_family == AF_INET ? sizeof(peer->Remote.Addr4) : sizeof(peer->Remote.Addr6);

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnSocketInit(&driver->WskProviderNpi, peer->Local.Addr4.sin_family, proto_tcp, (PSOCKADDR)&peer->Local,
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
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

    OvpnPeerZeroStats(&device->Stats);

    if (proto_tcp) {
        // start async connect
        status = OvpnSocketTcpConnect(socket, device, (PSOCKADDR)&peer->Remote);
    }

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS OvpnPeerSet(POVPN_DEVICE device, WDFREQUEST request)
{
    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    POVPN_SET_PEER peer = NULL;
    NTSTATUS status;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_SET_PEER), (PVOID*)&peer, nullptr));

    device->KeepaliveInterval = peer->KeepaliveInterval;
    device->KeepaliveTimeout = peer->KeepaliveTimeout;

    // keepalive xmit timer, sends ping packets
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerXmitCreate(device->WdfDevice, peer->KeepaliveInterval, &device->KeepaliveXmitTimer));
    OvpnTimerReset(device->KeepaliveXmitTimer, peer->KeepaliveInterval);

    // keepalive recv timer, detects keepalive timeout
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTimerRecvCreate(device->WdfDevice, &device->KeepaliveRecvTimer));
    OvpnTimerReset(device->KeepaliveRecvTimer, peer->KeepaliveTimeout);

    LOG_INFO("Keepalive", TraceLoggingValue(peer->KeepaliveInterval, "interval"), TraceLoggingValue(peer->KeepaliveTimeout, "timeout"));

done:
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
    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    LOG_INFO("Start VPN");

    NTSTATUS status;
    LOG_IF_NOT_NT_SUCCESS(status = OvpnAdapterCreate(device));

    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerNewKey(POVPN_DEVICE device, WDFREQUEST request)
{
    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    POVPN_CRYPTO_DATA cryptoData = NULL;
    NTSTATUS status;

    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_CRYPTO_DATA), (PVOID*)&cryptoData, nullptr));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoNewKey(&device->CryptoContext, cryptoData));

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnPeerSwapKeys(POVPN_DEVICE device)
{
    if (InterlockedCompareExchange(&device->UserspacePid, 0, 0) == 0) {
        LOG_ERROR("Peer not added");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    OvpnCryptoSwapKeys(&device->CryptoContext);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
OvpnPeerUninit(POVPN_DEVICE device)
{
    LONG existingPid = InterlockedCompareExchange(&device->UserspacePid, 0, 0);

    // by some reasons EVT_FILE_CLEANUP, which calls this function, is also called on driver reinstall,
    // when peer hasn't been added. Catch this case.
    if (existingPid == 0) {
        LOG_INFO("Peer not added.");
        return;
    }

    LOG_INFO("Uninitializing peer");

    BCRYPT_ALG_HANDLE aesAlgHandle = NULL, chachaAlgHandle = NULL;

    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);

    PWSK_SOCKET socket = device->Socket.Socket;
    device->Socket.Socket = NULL;

    OvpnTimerDestroy(&device->KeepaliveXmitTimer);
    OvpnTimerDestroy(&device->KeepaliveRecvTimer);

    aesAlgHandle = device->CryptoContext.AesAlgHandle;
    chachaAlgHandle = device->CryptoContext.ChachaAlgHandle;

    OvpnCryptoUninit(&device->CryptoContext);

    InterlockedExchange(&device->UserspacePid, 0);

    // OvpnAdapterDestroy and OvpnUdpCloseSocket require PASSIVE_LEVEL, so must release lock
    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

    OvpnCryptoUninitAlgHandles(aesAlgHandle, chachaAlgHandle);

    LOG_IF_NOT_NT_SUCCESS(OvpnSocketClose(socket));

    OvpnAdapterDestroy(device->Adapter);

    // flush buffers in control queue so that client won't get control channel messages from previous session
    while (LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->ControlRxBufferQueue)) {
        OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(entry, OVPN_RX_BUFFER, QueueListEntry);
        // return buffer back to pool
        OvpnRxBufferPoolPut(buffer);
    }
}
