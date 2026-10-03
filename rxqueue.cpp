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

#include <ntddk.h>
#include <wdf.h>
#include <netadaptercx.h>
#include <net/virtualaddress.h>
#include <net/checksum.h>

#include "driver.h"
#include "bufferpool.h"
#include "peer.h"
#include "rxqueue.h"
#include "netringiterator.h"
#include "trace.h"

EVT_PACKET_QUEUE_ADVANCE OvpnEvtRxQueueAdvance;

_Use_decl_annotations_
VOID
OvpnEvtRxQueueStart(NETPACKETQUEUE netPacketQueue)
{
    LOG_ENTER(TraceLoggingPointer(netPacketQueue, "RxQueue"));

    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);
    queue->Adapter->RxQueue = netPacketQueue;

    LOG_EXIT();
}

_Use_decl_annotations_
VOID
OvpnEvtRxQueueStop(NETPACKETQUEUE netPacketQueue)
{
    LOG_ENTER(TraceLoggingPointer(netPacketQueue, "RxQueue"));

    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);
    queue->Adapter->RxQueue = WDF_NO_HANDLE;

    LOG_EXIT();
}

_Use_decl_annotations_
VOID
OvpnEvtRxQueueDestroy(WDFOBJECT rxQueue)
{
    LOG_ENTER(TraceLoggingPointer(rxQueue, "RxQueue"));
    LOG_EXIT();
}

static inline UINT8
OvpnRxQueueGetLayer4Type(const VOID* buf, size_t len)
{
    UINT8 ret = NetPacketLayer4TypeUnspecified;

    if (len < sizeof(IPV4_HEADER))
        return ret;

    const auto ipv4hdr = (IPV4_HEADER*)buf;
    if (ipv4hdr->Version == IPV4_VERSION) {
        if (ipv4hdr->Protocol == IPPROTO_TCP)
            ret = NetPacketLayer4TypeTcp;
        else if (ipv4hdr->Protocol == IPPROTO_UDP)
            ret = NetPacketLayer4TypeUdp;
    }
    else if (ipv4hdr->Version == 6)  {
        if (len < sizeof(IPV6_HEADER))
            return ret;

        const auto ipv6hdr = (IPV6_HEADER*)buf;
        if (ipv6hdr->NextHeader == IPPROTO_TCP)
            ret = NetPacketLayer4TypeTcp;
        else if (ipv6hdr->NextHeader == IPPROTO_UDP)
            ret = NetPacketLayer4TypeUdp;
    }

    return ret;
}

// NetAdapterCx runs this queue on its own thread, as it does a NetAdapterCx NIC's receive path; on one
// core together they saturate it, packets queue, and one connection slows to its receive window. So
// the thread gets a home core away from the NIC's receive core, and transmit workers keep off both:
// an application woken by the ACKs this thread hands up then runs where no worker is encrypting.

// The physical core a processor belongs to, as a mask of its group.
static
KAFFINITY
OvpnRxQueueCoreMask(_In_ PROCESSOR_NUMBER* processor)
{
    union {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info;
        UCHAR bytes[sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) + 4 * sizeof(GROUP_AFFINITY)];
    } core;
    ULONG coreLen = sizeof(core);
    if (NT_SUCCESS(KeQueryLogicalProcessorRelationship(processor, RelationProcessorCore, &core.info, &coreLen)) &&
        (core.info.Processor.GroupCount > 0)) {
        return core.info.Processor.GroupMask[0].Mask;
    }
    return (KAFFINITY)1 << processor->Number;
}

// The NIC now receives the tunnel on rxIndex: pick a home core away from it for our receive and
// transmit queue threads, publish it for transmit workers to avoid, and make it the receive
// thread's ideal processor.
static
VOID
OvpnRxQueueChooseHome(_Inout_ OVPN_DEVICE* device, ULONG rxIndex)
{
    WriteULong64NoFence(&device->RxHomeIndexMask, 0);
    WriteULong64NoFence(&device->RxHomeAffinity, 0);

    PROCESSOR_NUMBER rx;
    if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(rxIndex, &rx))) {
        return;
    }

    KAFFINITY const rxCore = OvpnRxQueueCoreMask(&rx);
    KAFFINITY const active = KeQueryGroupAffinity(rx.Group);
    ULONG const span = (ULONG)RtlFindMostSignificantBit((ULONGLONG)active) + 1;
    ULONG const half = RtlNumberOfSetBitsUlongPtr(active) / 2;

    PROCESSOR_NUMBER home = {};
    home.Group = rx.Group;
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < span; ++i) {
        UCHAR const n = (UCHAR)((rx.Number + half + i) % span);
        KAFFINITY const bit = (KAFFINITY)1 << n;
        if ((active & bit) && !(rxCore & bit)) {
            home.Number = n;
            found = TRUE;
            break;
        }
    }
    if (!found) {
        return;
    }

    KAFFINITY const homeMask = OvpnRxQueueCoreMask(&home) & active;

    // transmit workers are placed by processor index
    ULONG64 indexMask = 0;
    for (ULONG n = 0; n < span; ++n) {
        if (homeMask & ((KAFFINITY)1 << n)) {
            PROCESSOR_NUMBER p = {};
            p.Group = home.Group;
            p.Number = (UCHAR)n;
            ULONG const index = KeGetProcessorIndexFromNumber(&p);
            if (index < 64) {
                indexMask |= 1ULL << index;
            }
        }
    }
    WriteULong64NoFence(&device->RxHomeIndexMask, indexMask);
    WriteNoFence(&device->RxHomeGroup, (LONG)home.Group);
    WriteULong64NoFence(&device->RxHomeAffinity, (ULONG64)homeMask);

    // the call returns the previous ideal processor in its buffer, so give it a copy
    PROCESSOR_NUMBER ideal = home;
    NTSTATUS const status = ZwSetInformationThread(ZwCurrentThread(), ThreadIdealProcessorEx, &ideal, sizeof(ideal));
    LOG_INFO("Rx queue thread given a home core", TraceLoggingValue(rxIndex, "rxCpu"),
        TraceLoggingValue(home.Number, "home"), TraceLoggingNTStatus(status, "status"));
}

// Steer only while one NIC receive core carries most of the traffic, as it does for a client or a
// server with one busy peer; a server's peers spread over many cores, and there is no core to avoid.
// Samples the core once per Advance: +1 when it repeats, -4 when it changes, so it must be about 80%.
#define OVPN_RX_HOME_SCORE_MAX 32
#define OVPN_RX_HOME_SCORE_ON 16

// Holds this thread to the home core for one Advance, choosing a new home first if the NIC's receive
// core moved; the thread is not ours, so the caller reverts it before returning.
static
BOOLEAN
OvpnRxQueueHoldHome(_Inout_ OVPN_DEVICE* device, _Out_ PGROUP_AFFINITY previous)
{
    RtlZeroMemory(previous, sizeof(*previous));

    // NetAdapterCx may run the queue in a DPC (Server 2022 does), where the current thread is
    // whichever one it interrupted: nothing to hold, and the thread calls are not allowed there
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    LONG const rxPlus1 = ReadNoFence(&device->NicRxCpuPlus1);
    if (rxPlus1 == 0) {
        return FALSE;
    }
    if ((ULONG)rxPlus1 == device->RxNicSamplePlus1) {
        device->RxNicScore = min(device->RxNicScore + 1, OVPN_RX_HOME_SCORE_MAX);
    }
    else if ((device->RxNicScore -= 4) <= 0) {
        device->RxNicSamplePlus1 = (ULONG)rxPlus1;
        device->RxNicScore = 1;
    }
    if (device->RxNicScore < OVPN_RX_HOME_SCORE_ON) {
        // no dominant core: drop the home, so transmit workers and the transmit queue thread go anywhere
        if (device->RxHomeForNicPlus1 != 0) {
            device->RxHomeForNicPlus1 = 0;
            WriteULong64NoFence(&device->RxHomeIndexMask, 0);
            WriteULong64NoFence(&device->RxHomeAffinity, 0);
        }
        return FALSE;
    }
    if (device->RxNicSamplePlus1 != device->RxHomeForNicPlus1) {
        device->RxHomeForNicPlus1 = device->RxNicSamplePlus1;
        OvpnRxQueueChooseHome(device, device->RxNicSamplePlus1 - 1);
    }
    USHORT const group = (USHORT)ReadNoFence(&device->RxHomeGroup);
    KAFFINITY const home = (KAFFINITY)ReadULong64NoFence((volatile DWORD64*)&device->RxHomeAffinity);
    if (home == 0) {
        return FALSE;
    }

    PROCESSOR_NUMBER here;
    KeGetCurrentProcessorNumberEx(&here);
    if ((here.Group == group) && (home & ((KAFFINITY)1 << here.Number))) {
        return FALSE;
    }

    GROUP_AFFINITY homeAffinity = {};
    homeAffinity.Group = group;
    homeAffinity.Mask = home;
    KeSetSystemGroupAffinityThread(&homeAffinity, previous);
    return TRUE;
}

_Use_decl_annotations_
VOID
OvpnEvtRxQueueAdvance(NETPACKETQUEUE netPacketQueue)
{
    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);
    OVPN_DEVICE* device = OvpnGetDeviceContext(queue->Adapter->WdfDevice);

    GROUP_AFFINITY previous;
    BOOLEAN const moved = OvpnRxQueueHoldHome(device, &previous);

    NET_RING_FRAGMENT_ITERATOR fi = NetRingGetAllFragments(queue->Rings);
    NET_RING_PACKET_ITERATOR pi = NetRingGetAllPackets(queue->Rings);
    while (NetFragmentIteratorHasAny(&fi)) {
        // get RX workitem, if any
        LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->DataRxBufferQueue);
        if (entry == NULL)
            break;

        OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(entry, OVPN_RX_BUFFER, QueueListEntry);

        NET_FRAGMENT* fragment = NetFragmentIteratorGetFragment(&fi);
        fragment->ValidLength = buffer->Len;
        fragment->Offset = 0;
        NET_FRAGMENT_VIRTUAL_ADDRESS* virtualAddr = NetExtensionGetFragmentVirtualAddress(&queue->VirtualAddressExtension, NetFragmentIteratorGetIndex(&fi));
        RtlCopyMemory(virtualAddr->VirtualAddress, buffer->Data, buffer->Len);

        InterlockedExchangeAddNoFence64(&device->Stats.TunBytesReceived, buffer->Len);

        NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
        packet->FragmentIndex = NetFragmentIteratorGetIndex(&fi);
        packet->FragmentCount = 1;

        packet->Layout = {};

        const auto checksum = NetExtensionGetPacketChecksum(&queue->ChecksumExtension, NetPacketIteratorGetIndex(&pi));

        // Win11/2022 and newer
        if (checksum) {
            checksum->Layer3 = NetPacketRxChecksumEvaluationValid; // IP checksum
            checksum->Layer4 = NetPacketRxChecksumEvaluationValid; // TCP/UDP checksum
            packet->Layout.Layer4Type = OvpnRxQueueGetLayer4Type(virtualAddr->VirtualAddress, buffer->Len);
        }

        NetFragmentIteratorAdvance(&fi);
        NetPacketIteratorAdvance(&pi);

        OvpnRxBufferPoolPut(buffer);

        InterlockedIncrementNoFence(&device->Stats.ReceivedDataPackets);
    }
    NetFragmentIteratorSet(&fi);
    NetPacketIteratorSet(&pi);

    if (moved) {
        KeRevertToUserGroupAffinityThread(&previous);
    }
}

_Use_decl_annotations_
VOID
OvpnEvtRxQueueSetNotificationEnabled(NETPACKETQUEUE queue, BOOLEAN notificationEnabled)
{
    POVPN_RXQUEUE rxQueue = OvpnGetRxQueueContext(queue);

    InterlockedExchangeNoFence(&rxQueue->NotificationEnabled, notificationEnabled);
}

_Use_decl_annotations_
VOID
OvpnEvtRxQueueCancel(NETPACKETQUEUE netPacketQueue)
{
    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);

    // mark all packets as "ignore"
    NET_RING_PACKET_ITERATOR pi = NetRingGetAllPackets(queue->Rings);
    while (NetPacketIteratorHasAny(&pi)) {
        NetPacketIteratorGetPacket(&pi)->Ignore = 1;
        NetPacketIteratorAdvance(&pi);
    }
    NetPacketIteratorSet(&pi);

    // return all fragments' ownership back to netadapter
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(queue->Rings);
    fragmentRing->BeginIndex = fragmentRing->EndIndex;
}

_Use_decl_annotations_
VOID
OvpnRxQueueInitialize(NETPACKETQUEUE netPacketQueue, POVPN_ADAPTER adapter)
{
    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);
    queue->Adapter = adapter;
    queue->Rings = NetRxQueueGetRingCollection(netPacketQueue);

    NET_EXTENSION_QUERY extension;
    NET_EXTENSION_QUERY_INIT(&extension, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_NAME, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_VERSION_1, NetExtensionTypeFragment);
    NetRxQueueGetExtension(netPacketQueue, &extension, &queue->VirtualAddressExtension);

    // Query checksum packet extension offset and store it in the context
    NET_EXTENSION_QUERY_INIT(&extension, NET_PACKET_EXTENSION_CHECKSUM_NAME, NET_PACKET_EXTENSION_CHECKSUM_VERSION_1, NetExtensionTypePacket);
    NetRxQueueGetExtension(netPacketQueue, &extension, &queue->ChecksumExtension);
}
