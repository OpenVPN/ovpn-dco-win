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

#include <ntddk.h>
#include <wdf.h>
#include <netadaptercx.h>

#include <net/virtualaddress.h>

#include "crypto.h"
#include "driver.h"
#include "mss.h"
#include "trace.h"
#include "netringiterator.h"
#include "timer.h"
#include "txqueue.h"
#include "socket.h"
#include "peer.h"

static
BOOLEAN
OvpnTxAreSockaddrEqual(const SOCKADDR* addr1, const SOCKADDR* addr2) {
    // First, check if the address families are the same
    if (addr1->sa_family != addr2->sa_family) {
        return 0;  // Not equal if the families are different
    }

    if (addr1->sa_family == AF_INET) {
        // Compare IPv4 addresses
        SOCKADDR_IN* ipv4_1 = (SOCKADDR_IN*)addr1;
        SOCKADDR_IN* ipv4_2 = (SOCKADDR_IN*)addr2;
        return (ipv4_1->sin_addr.s_addr == ipv4_2->sin_addr.s_addr &&
            ipv4_1->sin_port == ipv4_2->sin_port);
    }
    else if (addr1->sa_family == AF_INET6) {
        // Compare IPv6 addresses
        SOCKADDR_IN6* ipv6_1 = (SOCKADDR_IN6*)addr1;
        SOCKADDR_IN6* ipv6_2 = (SOCKADDR_IN6*)addr2;
        SIZE_T result = RtlCompareMemory(&ipv6_1->sin6_addr, &ipv6_2->sin6_addr, sizeof(ipv6_1->sin6_addr));
        return (result == sizeof(ipv6_1->sin6_addr) &&
            ipv6_1->sin6_port == ipv6_2->sin6_port);
    }

    // If the address family is neither AF_INET nor AF_INET6, return not equal
    return 0;
}

BOOLEAN
OvpnCheckRecursiveRoutingIPv4(SOCKADDR_IN* transportAdds, UCHAR* buffer, SIZE_T bufferLength, BOOLEAN tcp)
{
    if (transportAdds->sin_family != AF_INET || bufferLength < sizeof(IPV4_HEADER))
        return FALSE;  // Not an IPv4 peer or packet too short

    // Extract pointers to avoid repeated FIELD_OFFSET calculations
    IN_ADDR* srcAddr = (IN_ADDR*)(buffer + FIELD_OFFSET(IPV4_HEADER, SourceAddress));
    IN_ADDR* dstAddr = (IN_ADDR*)(buffer + FIELD_OFFSET(IPV4_HEADER, DestinationAddress));
    UINT8 packetProtocol = buffer[FIELD_OFFSET(IPV4_HEADER, Protocol)];

    // Validate the transport protocol
    if ((tcp && packetProtocol != IPPROTO_TCP) || (!tcp && packetProtocol != IPPROTO_UDP))
        return FALSE;

    // Extract IP header length
    UINT8 ipHeaderLength = (buffer[0] & 0x0F) << 2;

    // Ensure transport header is accessible
    if (bufferLength < ipHeaderLength + sizeof(UINT16) * 2)
        return FALSE;

    // Read transport header efficiently
    UCHAR* transportHeader = buffer + ipHeaderLength;
    UINT16 packetSrcPort = RtlUshortByteSwap(*(UINT16*)(transportHeader));
    UINT16 packetDstPort = RtlUshortByteSwap(*(UINT16*)(transportHeader + 2));
    UINT16 peerPort = RtlUshortByteSwap(transportAdds->sin_port);

    // Check for recursive routing
    if (packetDstPort == peerPort &&
        RtlCompareMemory(dstAddr, &transportAdds->sin_addr, sizeof(IN_ADDR)) == sizeof(IN_ADDR))
    {
        LOG_WARN("Recursive routing detected (IPv4), packet dropped",
            TraceLoggingIPv4Address(srcAddr->S_un.S_addr, "saddr"),
            TraceLoggingIPv4Address(dstAddr->S_un.S_addr, "daddr"),
            TraceLoggingUInt16(packetSrcPort, "sport"),
            TraceLoggingUInt16(packetDstPort, "dport"),
            TraceLoggingUInt8(packetProtocol, "protocol"));
        return TRUE;
    }

    return FALSE;
}

BOOLEAN
OvpnCheckRecursiveRoutingIPv6(SOCKADDR_IN6* transportAddr, UCHAR* buffer, SIZE_T bufferLength, BOOLEAN tcp)
{
    if (transportAddr->sin6_family != AF_INET6 || bufferLength < sizeof(IPV6_HEADER))
        return FALSE;  // Not an IPv6 peer or packet too short

    // Extract pointers to avoid repeated FIELD_OFFSET calculations
    IN6_ADDR* srcAddr = (IN6_ADDR*)(buffer + FIELD_OFFSET(IPV6_HEADER, SourceAddress));
    IN6_ADDR* dstAddr = (IN6_ADDR*)(buffer + FIELD_OFFSET(IPV6_HEADER, DestinationAddress));
    UINT8 packetProtocol = buffer[FIELD_OFFSET(IPV6_HEADER, NextHeader)];

    // Validate the transport protocol
    if ((tcp && packetProtocol != IPPROTO_TCP) || (!tcp && packetProtocol != IPPROTO_UDP))
        return FALSE;

    // Ensure transport header is accessible
    if (bufferLength < sizeof(IPV6_HEADER) + sizeof(UINT16) * 2)
        return FALSE;

    // Read transport header efficiently
    UCHAR* transportHeader = buffer + sizeof(IPV6_HEADER);
    UINT16 packetSrcPort = RtlUshortByteSwap(*(UINT16*)(transportHeader));
    UINT16 packetDstPort = RtlUshortByteSwap(*(UINT16*)(transportHeader + 2));
    UINT16 peerPort = RtlUshortByteSwap(transportAddr->sin6_port);

    // Check for recursive routing
    if (packetDstPort == peerPort &&
        RtlCompareMemory(dstAddr, &transportAddr->sin6_addr, sizeof(IN6_ADDR)) == sizeof(IN6_ADDR))
    {
        LOG_WARN("Recursive routing detected (IPv6), packet dropped",
            TraceLoggingIPv6Address(srcAddr->u.Byte, "saddr"),
            TraceLoggingIPv6Address(dstAddr->u.Byte, "daddr"),
            TraceLoggingUInt16(packetSrcPort, "sport"),
            TraceLoggingUInt16(packetDstPort, "dport"),
            TraceLoggingUInt8(packetProtocol, "protocol"));
        return TRUE;
    }

    return FALSE;
}

// The peer a plaintext packet belongs to, with its MSS clamp applied. NULL means there is
// nowhere to send it.
static
OvpnPeerContext*
OvpnTxFindPeer(_In_ POVPN_DEVICE device, _In_reads_bytes_(len) UCHAR* data, SIZE_T len, BOOLEAN tcp)
{
    OvpnPeerContext* peer = NULL;

    if (OvpnMssIsIPv4(data, len)) {
        auto addr = ((IPV4_HEADER*)data)->DestinationAddress;

        peer = OvpnFindPeerVPN4(device, addr, FALSE);
        if (peer == nullptr) {
            peer = device->IRoutesIPV4.Find(reinterpret_cast<UCHAR*>(&addr));
        }

        if ((device->Mode == OVPN_MODE_P2P) && (peer != nullptr) && (OvpnCheckRecursiveRoutingIPv4(&peer->TransportAddrs.Remote.IPv4, data, len, tcp))) {
            OvpnPeerCtxRelease(peer);
            peer = nullptr;
        }

        if (peer != nullptr) {
            OvpnMssDoIPv4(data, len, peer->MSS);
        }
    } else if (OvpnMssIsIPv6(data, len)) {
        auto addr = ((IPV6_HEADER*)data)->DestinationAddress;

        peer = OvpnFindPeerVPN6(device, addr, FALSE);
        if (peer == nullptr) {
            peer = device->IRoutesIPV6.Find(reinterpret_cast<UCHAR*>(&addr));
        }

        if ((device->Mode == OVPN_MODE_P2P) && (peer != nullptr) && (OvpnCheckRecursiveRoutingIPv6(&peer->TransportAddrs.Remote.IPv6, data, len, tcp))) {
            OvpnPeerCtxRelease(peer);
            peer = nullptr;
        }

        if (peer != nullptr) {
            OvpnMssDoIPv6(data, len, peer->MSS);
        }
    }

    return peer;
}

// Encrypt in place under the peer's transmit lock, held by the caller. On failure the
// buffer is left for the caller to dispose of.
_Must_inspect_result_
static
NTSTATUS
OvpnTxEncryptLocked(_In_ OvpnPeerContext* peer, _In_ OVPN_TX_BUFFER* buffer)
{
    OvpnCryptoTxContext* tx = &peer->CryptoContext.Tx;

    if (!tx->Encrypt) {
        // LOG_WARN("CryptoContext not initialized");
        return STATUS_INVALID_DEVICE_STATE;
    }

    const OvpnCryptoPacketLayout layout = tx->Layout;

    if (layout.FrontLen > OVPN_BUFFER_HEADROOM) {
        LOG_ERROR("Packet header exceeds tx headroom",
                  TraceLoggingValue(layout.FrontLen, "front"),
                  TraceLoggingValue(OVPN_BUFFER_HEADROOM, "headroom"));
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if ((buffer->Len + layout.FrontLen + layout.TailLen) > (OVPN_DCO_MTU_MAX + OVPN_BUFFER_HEADROOM + OVPN_BUFFER_TAILROOM)) {
        LOG_ERROR("Packet exceeds tx buffer capacity",
                  TraceLoggingValue(buffer->Len, "len"),
                  TraceLoggingValue(layout.FrontLen, "front"),
                  TraceLoggingValue(layout.TailLen, "tail"));
        return STATUS_INVALID_BUFFER_SIZE;
    }

    OvpnTxBufferPush(buffer, layout.FrontLen);
    OvpnBufferPut(buffer, layout.TailLen);

    return OvpnCryptoEncrypt(tx, buffer->Data, buffer->Len);
}

// Hand one encrypted buffer to the socket. Datagrams for one destination are chained and
// sent together by the caller; the buffer is consumed either way.
_Must_inspect_result_
static
NTSTATUS
OvpnTxSubmit(_In_ OvpnSocketRef* socket, _In_ OVPN_TX_BUFFER* buffer, _In_ const OVPN_REMOTE_ADDR& remoteAddr,
    _Inout_ OVPN_TX_BUFFER** head, _Inout_ OVPN_TX_BUFFER** tail, _Inout_ SOCKADDR_STORAGE* headSockaddr)
{
    // start async send, this will return ciphertext buffer to the pool
    if (socket->Tcp) {
        return OvpnSocketSend(socket, buffer, NULL);
    }

    // for UDP we use SendMessages to send multiple datagrams at once
    // here we only append WSK_BUF to the list

    buffer->WskBufList.Buffer.Length = buffer->Len;
    buffer->WskBufList.Buffer.Mdl = buffer->Mdl;
    buffer->WskBufList.Buffer.Offset = FIELD_OFFSET(OVPN_TX_BUFFER, Head) + (ULONG)(buffer->Data - buffer->Head);

    // If this peer is different (head sockaddr != peer sockaddr) to the previous buffer chain peers,
    // then flush those and restart with a new buffer list.

    if ((*head != NULL) && !(OvpnTxAreSockaddrEqual((const SOCKADDR*)headSockaddr, (const SOCKADDR*)&remoteAddr)))
    {
        LOG_IF_NOT_NT_SUCCESS(OvpnSocketSend(socket, *head, (SOCKADDR*)headSockaddr));
        *head = buffer;
        *tail = buffer;
        OvpnSocketCopyRemoteToSockaddr(remoteAddr, headSockaddr);
    } else {
        if (*head == NULL) {
            *head = buffer;
            OvpnSocketCopyRemoteToSockaddr(remoteAddr, headSockaddr);
        }
        else {
            (*tail)->WskBufList.Next = &buffer->WskBufList;
        }

        *tail = buffer;
    }

    return STATUS_SUCCESS;
}

// Encrypt one buffer, hand it to the socket and account for it. Consumed either way.
_Must_inspect_result_
static
NTSTATUS
OvpnTxEncryptAndSend(_In_ POVPN_DEVICE device, _In_ OvpnSocketRef* socket, _In_ OvpnPeerContext* peer,
    _In_ OVPN_TX_BUFFER* buffer, _Inout_ OVPN_TX_BUFFER** head, _Inout_ OVPN_TX_BUFFER** tail,
    _Inout_ SOCKADDR_STORAGE* headSockaddr)
{
    InterlockedExchangeAddNoFence64(&device->Stats.TunBytesSent, buffer->Len);
    InterlockedExchangeAddNoFence64(&peer->VpnTxBytes, buffer->Len);

    KIRQL irql = ExAcquireSpinLockShared(&peer->TxLock);
    auto remoteAddr = peer->TransportAddrs.Remote;
    NTSTATUS status = OvpnTxEncryptLocked(peer, buffer);
    ExReleaseSpinLockShared(&peer->TxLock, irql);

    // Moving the epoch on is the only thing here that writes the key, so it is the only
    // thing that needs the lock to itself. The buffer is already prepared, so only the
    // encryption repeats.
    if (status == STATUS_RETRY) {
        irql = ExAcquireSpinLockExclusive(&peer->TxLock);
        status = OvpnCryptoAdvanceSendKey(&peer->CryptoContext.Tx);
        ExReleaseSpinLockExclusive(&peer->TxLock, irql);

        if (NT_SUCCESS(status)) {
            irql = ExAcquireSpinLockShared(&peer->TxLock);
            status = OvpnCryptoEncrypt(&peer->CryptoContext.Tx, buffer->Data, buffer->Len);
            ExReleaseSpinLockShared(&peer->TxLock, irql);
        }
    }

    if (!NT_SUCCESS(status)) {
        OvpnTxBufferPoolPut(buffer);
        return status;
    }

    InterlockedExchangeAddNoFence64(&peer->LinkTxBytes, buffer->Len);

    status = OvpnTxSubmit(socket, buffer, remoteAddr, head, tail, headSockaddr);

    OvpnTimerResetXmit(peer->Timer);

    return status;
}

// The worker a flow belongs to, so its packets keep their order. The ports are in the
// hash because addresses alone would put every flow between two machines together.
static
ULONG
OvpnTxFlowHash(_In_reads_bytes_(len) UCHAR const* data, SIZE_T len)
{
    ULONG h = 0;

    if ((len >= sizeof(IPV4_HEADER)) && ((data[0] >> 4) == 4)) {
        IPV4_HEADER const* ip = (IPV4_HEADER const*)data;
        SIZE_T const hdrLen = (SIZE_T)ip->HeaderLength << 2;

        h = ip->SourceAddress.S_un.S_addr ^ ip->DestinationAddress.S_un.S_addr;

        if (((ip->Protocol == IPPROTO_TCP) || (ip->Protocol == IPPROTO_UDP)) &&
            (len >= (hdrLen + sizeof(UINT32)))) {
            h ^= *(UINT32 UNALIGNED const*)(data + hdrLen);
        }
    }
    else if ((len >= sizeof(IPV6_HEADER)) && ((data[0] >> 4) == 6)) {
        IPV6_HEADER const* ip = (IPV6_HEADER const*)data;
        UINT32 UNALIGNED const* addrs = (UINT32 UNALIGNED const*)&ip->SourceAddress;

        for (int i = 0; i < 8; ++i) {
            h ^= addrs[i];
        }

        if (((ip->NextHeader == IPPROTO_TCP) || (ip->NextHeader == IPPROTO_UDP)) &&
            (len >= (sizeof(IPV6_HEADER) + sizeof(UINT32)))) {
            h ^= *(UINT32 UNALIGNED const*)(data + sizeof(IPV6_HEADER));
        }
    }

    h ^= h >> 16;
    h ^= h >> 8;

    return h;
}

// Encrypt and send everything handed to this worker since it last ran. It outlives the
// ring pass that queued the work, so it holds the socket itself.
// Notification armed means the framework has stopped calling Advance, so once there is
// room again it must be told to resume, or what is left on the ring stays there.
static
VOID
OvpnTxQueueResume(_In_ POVPN_TXQUEUE queue)
{
    if (InterlockedExchange(&queue->NotificationEnabled, FALSE) == TRUE) {
        NetTxQueueNotifyMoreCompletedPacketsAvailable((NETPACKETQUEUE)WdfObjectContextGetObject(queue));
    }
}

KDEFERRED_ROUTINE OvpnTxWorkerDpc;

_Use_decl_annotations_
VOID
OvpnTxWorkerDpc(KDPC* dpc, PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    POVPN_TX_WORKER worker = (POVPN_TX_WORKER)context;
    POVPN_DEVICE device = worker->Device;

    // take the whole queue in one go, so the work runs without the lock
    LIST_ENTRY work;
    KeAcquireSpinLockAtDpcLevel(&worker->Lock);
    OvpnListMoveAll(&worker->Queue, &work);
    KeReleaseSpinLockFromDpcLevel(&worker->Lock);

    if (IsListEmpty(&work)) {
        return;
    }

    OvpnSocketRef socket;
    BOOLEAN const haveSocket = OvpnSocketAcquire(device, &socket);

    OVPN_TX_BUFFER* head = NULL;
    OVPN_TX_BUFFER* tail = NULL;
    SOCKADDR_STORAGE headSockaddr = { 0 };

    while (!IsListEmpty(&work)) {
        OVPN_TX_BUFFER* buffer = CONTAINING_RECORD(RemoveHeadList(&work), OVPN_TX_BUFFER, PoolListEntry);
        OvpnPeerContext* peer = buffer->Peer;
        buffer->Peer = NULL;
        InterlockedDecrement(&worker->Owner->Queued);

        NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
        if (haveSocket) {
            status = OvpnTxEncryptAndSend(device, &socket, peer, buffer, &head, &tail, &headSockaddr);
        }
        else {
            OvpnTxBufferPoolPut(buffer);
        }

        if (!NT_SUCCESS(status)) {
            InterlockedIncrementNoFence(&device->Stats.LostOutDataPackets);
        }

        OvpnPeerCtxRelease(peer);
    }

    if (haveSocket) {
        if (head != NULL) {
            LOG_IF_NOT_NT_SUCCESS(OvpnSocketSend(&socket, head, (SOCKADDR*)&headSockaddr));
        }

        OvpnSocketRelease(device);
    }

    OvpnTxQueueResume(worker->Owner);
}

// Hand a buffer to the worker that owns its flow, with the caller's reference on the peer.
static
VOID
OvpnTxToWorker(_In_ POVPN_TXQUEUE queue, _In_ OvpnPeerContext* peer, _In_ OVPN_TX_BUFFER* buffer, ULONG hash,
    ULONG workerCount)
{
    // Not on the core that receives the tunnel, the busiest one: a flow whose ACKs
    // are encrypted there too saturates it, and the whole tunnel slows down.
    ULONG index = hash % workerCount;
    if (queue->Workers[index].Processor == ReadULongNoFence(&peer->RxProcessor)) {
        index = (index + 1) % workerCount;
    }
    POVPN_TX_WORKER worker = &queue->Workers[index];

    buffer->Peer = peer;

    KIRQL irql;
    KeAcquireSpinLock(&worker->Lock, &irql);
    InsertTailList(&worker->Queue, &buffer->PoolListEntry);
    KeReleaseSpinLock(&worker->Lock, irql);

    InterlockedIncrement(&queue->Queued);
}

// Wake the workers once per ring pass. Waking per packet costs more than it saves: a
// pass is what makes a batch worth sending.
static
VOID
OvpnTxWakeWorkers(_In_ POVPN_TXQUEUE queue)
{
    for (ULONG i = 0; i < queue->WorkerCount; ++i) {
        POVPN_TX_WORKER worker = &queue->Workers[i];

        // a stale answer here only costs an empty run, which the worker handles
        if (!IsListEmpty(&worker->Queue)) {
            KeInsertQueueDpc(&worker->Dpc, NULL, NULL);
        }
    }
}

static
VOID
OvpnTxWorkersInitialize(_In_ POVPN_TXQUEUE queue, _In_ POVPN_DEVICE device)
{
    queue->WorkerCount = 0;

    ULONG const processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ULONG const count = min(processors, OVPN_TX_WORKERS_MAX);

    if (count < 2) {
        return;
    }

    for (ULONG i = 0; i < count; ++i) {
        POVPN_TX_WORKER worker = &queue->Workers[i];

        worker->Device = device;
        worker->Owner = queue;
        worker->Index = i;
        KeInitializeSpinLock(&worker->Lock);
        InitializeListHead(&worker->Queue);
        KeInitializeDpc(&worker->Dpc, OvpnTxWorkerDpc, worker);

        // At medium importance a busy target runs it at its next clock tick, so the
        // flow's ACKs leave in clumps and the sender bursts past the receiver's queue.
        KeSetImportanceDpc(&worker->Dpc, MediumHighImportance);

        // Spread out, so hyperthread siblings do not get two workers. The index counts
        // across every processor group, so it needs the Ex form, which carries the group.
        PROCESSOR_NUMBER target;
        worker->Processor = (i * processors) / count;
        if (NT_SUCCESS(KeGetProcessorNumberFromIndex(worker->Processor, &target))) {
            LOG_IF_NOT_NT_SUCCESS(KeSetTargetProcessorDpcEx(&worker->Dpc, &target));
        }
    }

    queue->WorkerCount = count;

    LOG_INFO("Tx workers started", TraceLoggingValue(count, "workers"),
             TraceLoggingValue(processors, "processors"));
}

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
OvpnTxWorkersStop(_In_ POVPN_TXQUEUE queue)
{
    ULONG const count = InterlockedExchange((LONG*)&queue->WorkerCount, 0);
    if (count == 0) {
        return;
    }

    for (ULONG i = 0; i < count; ++i) {
        KeRemoveQueueDpc(&queue->Workers[i].Dpc);
    }

    // KeRemoveQueueDpc says nothing about a dpc the dispatcher has already taken off its
    // list and is about to call, which would then run on the freed queue context. This
    // waits for those, and is why the drain belongs at passive level.
    KeFlushQueuedDpcs();

    for (ULONG i = 0; i < count; ++i) {
        POVPN_TX_WORKER worker = &queue->Workers[i];

        KIRQL irql;
        KeAcquireSpinLock(&worker->Lock, &irql);
        while (!IsListEmpty(&worker->Queue)) {
            OVPN_TX_BUFFER* buffer = CONTAINING_RECORD(RemoveHeadList(&worker->Queue), OVPN_TX_BUFFER, PoolListEntry);
            OvpnPeerContext* peer = buffer->Peer;
            buffer->Peer = NULL;
            OvpnTxBufferPoolPut(buffer);
            InterlockedDecrement(&queue->Queued);
            InterlockedIncrementNoFence(&queue->Workers[i].Device->Stats.LostOutDataPackets);
            if (peer != NULL) {
                OvpnPeerCtxRelease(peer);
            }
        }
        KeReleaseSpinLock(&worker->Lock, irql);
    }
}

_Must_inspect_result_
static
NTSTATUS
OvpnTxProcessPacket(_In_ POVPN_DEVICE device, _In_ OvpnSocketRef* socket, _In_ POVPN_TXQUEUE queue,
    _In_ NET_RING_PACKET_ITERATOR *pi, _Inout_ OVPN_TX_BUFFER **head, _Inout_ OVPN_TX_BUFFER** tail,
    _Inout_ SOCKADDR_STORAGE *headSockaddr)
{
    NET_RING_FRAGMENT_ITERATOR fi = NetPacketIteratorGetFragments(pi);

    OvpnPeerContext* peer = NULL;

    // Fixed for the queue's life, and read here so the gotos below do not jump over it.
    ULONG const workerCount = queue->WorkerCount;

    // get buffer into which we gather plaintext fragments and do in-place encryption
    OVPN_TX_BUFFER* buffer;
    NTSTATUS status;
    LOG_IF_NOT_NT_SUCCESS(status = OvpnTxBufferPoolGet(device->TxBufferPool, &buffer));
    if (!NT_SUCCESS(status)) {
        // Through out: so the fragments go back with the packet. Returning here kept them,
        // and enough of those fill the fragment ring and stop the framework posting at all.
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    // gather fragments into single buffer
    while (NetFragmentIteratorHasAny(&fi)) {
        // get fragment payload
        NET_FRAGMENT* fragment = NetFragmentIteratorGetFragment(&fi);

        if ((buffer->Len + fragment->ValidLength) > OVPN_DCO_MTU_MAX) {
            LOG_WARN("Packet max length exceeded, dropping",
                     TraceLoggingValue(buffer->Len, "currentLen"),
                     TraceLoggingValue(fragment->ValidLength, "lenToAdd"),
                     TraceLoggingValue(OVPN_DCO_MTU_MAX - buffer->Len, "spaceLeft"));
            OvpnTxBufferPoolPut(buffer);
            status = STATUS_INVALID_BUFFER_SIZE;
            goto out;
        }

        NET_FRAGMENT_VIRTUAL_ADDRESS* virtualAddr = NetExtensionGetFragmentVirtualAddress(
            &queue->VirtualAddressExtension, NetFragmentIteratorGetIndex(&fi));

        RtlCopyMemory(OvpnBufferPut(buffer, fragment->ValidLength),
            (UCHAR const*)virtualAddr->VirtualAddress + fragment->Offset, fragment->ValidLength);

        NetFragmentIteratorAdvance(&fi);
    }

    peer = OvpnTxFindPeer(device, buffer->Data, buffer->Len, socket->Tcp);

    if (peer == nullptr) {
        status = STATUS_ADDRESS_NOT_ASSOCIATED;
        OvpnTxBufferPoolPut(buffer);
        goto out;
    }

    // a stream has to leave in the order it was encrypted, so TCP stays on this thread
    if ((workerCount > 0) && !socket->Tcp) {
        // A worker buffer is not returned to the pool until its send completes, so the
        // count in flight - and the pool behind it - grows without bound when sends lag.
        // Over the cap, drop this packet rather than grow.
        if (InterlockedCompareExchange(&device->TxDataInFlight, 0, 0) >= OVPN_TX_DATA_INFLIGHT_MAX) {
            OvpnPeerCtxRelease(peer);
            OvpnTxBufferPoolPut(buffer);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
        InterlockedIncrement(&device->TxDataInFlight);
        buffer->CountedInFlight = TRUE;
        // the reference goes with the buffer
        OvpnTxToWorker(queue, peer, buffer, OvpnTxFlowHash(buffer->Data, buffer->Len), workerCount);
        goto out;
    }

    status = OvpnTxEncryptAndSend(device, socket, peer, buffer, head, tail, headSockaddr);

    OvpnPeerCtxRelease(peer);

out:
    // update fragment ring's BeginIndex to indicate that we've processes all fragments
    NET_PACKET* packet = NetPacketIteratorGetPacket(pi);
    NET_RING* const fragmentRing = NetRingCollectionGetFragmentRing(fi.Iterator.Rings);
    UINT32 const lastFragmentIndex = NetRingAdvanceIndex(fragmentRing, packet->FragmentIndex, packet->FragmentCount);

    fragmentRing->BeginIndex = lastFragmentIndex;

    return status;
}

_Use_decl_annotations_
VOID
OvpnEvtTxQueueAdvance(NETPACKETQUEUE netPacketQueue)
{
    POVPN_TXQUEUE queue = OvpnGetTxQueueContext(netPacketQueue);
    NET_RING_PACKET_ITERATOR pi = NetRingGetAllPackets(queue->Rings);
    POVPN_DEVICE device = OvpnGetDeviceContext(queue->Adapter->WdfDevice);
    BOOLEAN packetSent = false;

    // Held for the whole batch, released after the flush at the end. Nothing is returned
    // to the framework without a socket: the packets stay on the ring for the next pass,
    // and EvtTxQueueCancel gives them all back when the datapath stops.
    OvpnSocketRef socket;
    if (!OvpnSocketAcquire(device, &socket)) {
        return;
    }
    BOOLEAN isTcp = socket.Tcp;

    OVPN_TX_BUFFER* txBufferHead = NULL;
    OVPN_TX_BUFFER* txBufferTail = NULL;
    SOCKADDR_STORAGE headSockaddr = {0};

    // Stop once the workers are a queue-depth behind and let the framework poll again.
    // The packets stay on the ring, which is the whole point: a buffer taken off it is
    // held until a worker sends it, so without this the pool grows to hold the backlog.
    LONG const queuedMax = (LONG)(queue->WorkerCount * OVPN_TX_QUEUED_MAX_PER_WORKER);

    while (NetPacketIteratorHasAny(&pi)) {
        if ((queue->WorkerCount > 0) &&
            (InterlockedCompareExchange(&queue->Queued, 0, 0) >= queuedMax)) {
            break;
        }

        NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
        NTSTATUS status = STATUS_SUCCESS;
        if (!packet->Ignore && !packet->Scratch) {
            status = OvpnTxProcessPacket(device, &socket, queue, &pi, &txBufferHead, &txBufferTail, &headSockaddr);
            if (!NT_SUCCESS(status)) {
                InterlockedIncrementNoFence(&device->Stats.LostOutDataPackets);
            }
            else {
                packetSent = true;
            }
        }

        NetPacketIteratorAdvance(&pi);
        if (!NT_SUCCESS(status)) {
            break;
        }
    }
    NetPacketIteratorSet(&pi);

    if (packetSent && !isTcp && txBufferHead != NULL) {
        // this will use WskSendMessages to send buffers list which we constructed before
        LOG_IF_NOT_NT_SUCCESS(OvpnSocketSend(&socket, txBufferHead, (SOCKADDR*)&headSockaddr));
    }

    OvpnSocketRelease(device);

    if (queue->WorkerCount > 0) {
        OvpnTxWakeWorkers(queue);
    }
}

_Use_decl_annotations_
VOID
OvpnTxQueueInitialize(NETPACKETQUEUE netPacketQueue, POVPN_ADAPTER adapter)
{
    POVPN_TXQUEUE queue = OvpnGetTxQueueContext(netPacketQueue);
    queue->Adapter = adapter;
    queue->Rings = NetTxQueueGetRingCollection(netPacketQueue);

    NET_EXTENSION_QUERY extension;
    NET_EXTENSION_QUERY_INIT(&extension, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_NAME, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_VERSION_1, NetExtensionTypeFragment);
    NetTxQueueGetExtension(netPacketQueue, &extension, &queue->VirtualAddressExtension);

    OvpnTxWorkersInitialize(queue, OvpnGetDeviceContext(adapter->WdfDevice));
}

// Cleanup rather than destroy: the drain waits on queued dpcs, which needs passive level,
// and runs while the buffer pool it returns buffers to is still alive. Both come from
// NetAdapterCx, so assert the level - asking WDF for it with ExecutionLevel stops the
// device starting.
_Use_decl_annotations_
VOID
OvpnEvtTxQueueCleanup(WDFOBJECT txQueue)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    OvpnTxWorkersStop(OvpnGetTxQueueContext((NETPACKETQUEUE)txQueue));
}

_Use_decl_annotations_
VOID
OvpnEvtTxQueueSetNotificationEnabled(NETPACKETQUEUE queue, BOOLEAN notificationEnabled)
{
    POVPN_TXQUEUE txQueue = OvpnGetTxQueueContext(queue);
    InterlockedExchange(&txQueue->NotificationEnabled, notificationEnabled);

    // The workers may have made room before this was armed, and then nothing would wake
    // the queue. Only with packets waiting, or an idle queue would poll forever.
    if (notificationEnabled && (txQueue->WorkerCount > 0)) {
        NET_RING const* packets = NetRingCollectionGetPacketRing(txQueue->Rings);
        LONG const queuedMax = (LONG)(txQueue->WorkerCount * OVPN_TX_QUEUED_MAX_PER_WORKER);
        if ((packets->BeginIndex != packets->EndIndex) &&
            (InterlockedCompareExchange(&txQueue->Queued, 0, 0) < queuedMax)) {
            OvpnTxQueueResume(txQueue);
        }
    }
}

_Use_decl_annotations_
VOID
OvpnEvtTxQueueCancel(NETPACKETQUEUE netPacketQueue)
{
    // mark all packets as "ignore"
    POVPN_TXQUEUE queue = OvpnGetTxQueueContext(netPacketQueue);
    NET_RING_PACKET_ITERATOR pi = NetRingGetAllPackets(queue->Rings);
    while (NetPacketIteratorHasAny(&pi)) {
        // we cannot modify Ignore here, otherwise Verifier will bark on us
        NetPacketIteratorGetPacket(&pi)->Scratch = 1;
        NetPacketIteratorAdvance(&pi);
    }
    NetPacketIteratorSet(&pi);

    // return all fragments' ownership back to netadapter
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(queue->Rings);
    fragmentRing->BeginIndex = fragmentRing->EndIndex;
}
