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

_Use_decl_annotations_
VOID
OvpnEvtRxQueueAdvance(NETPACKETQUEUE netPacketQueue)
{
    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);
    OVPN_DEVICE* device = OvpnGetDeviceContext(queue->Adapter->WdfDevice);

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
