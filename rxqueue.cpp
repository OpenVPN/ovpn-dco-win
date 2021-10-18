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

#include "driver.h"
#include "bufferpool.h"
#include "rxqueue.h"
#include "netringiterator.h"

EVT_PACKET_QUEUE_ADVANCE OvpnEvtRxQueueAdvance;

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

        OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(entry, OVPN_RX_BUFFER, ListEntry);

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
}
