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

#include "crypto.h"
#include "driver.h"
#include "trace.h"
#include "netringiterator.h"
#include "timer.h"
#include "txqueue.h"
#include "socket.h"

_Must_inspect_result_
_Requires_shared_lock_held_(device->SpinLock)
static
NTSTATUS
OvpnTxSendPacket(_In_ POVPN_DEVICE device, _In_ POVPN_TXQUEUE queue, _In_ NET_RING_PACKET_ITERATOR *pi)
{
    NET_RING_FRAGMENT_ITERATOR fi = NetPacketIteratorGetFragments(pi);

    // get buffer into which we gather plaintext fragments and do in-place encryption
    OVPN_TX_BUFFER* buffer;
    NTSTATUS status;
    LOG_IF_NOT_NT_SUCCESS(status = OvpnTxBufferPoolGet(device->TxBufferPool, &buffer));
    if (!NT_SUCCESS(status)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // gather fragments into single buffer
    while (NetFragmentIteratorHasAny(&fi)) {
        // get fragment payload
        NET_FRAGMENT* fragment = NetFragmentIteratorGetFragment(&fi);
        NET_FRAGMENT_VIRTUAL_ADDRESS* virtualAddr = NetExtensionGetFragmentVirtualAddress(
            &queue->VirtualAddressExtension, NetFragmentIteratorGetIndex(&fi));

        RtlCopyMemory(OvpnTxBufferPut(buffer, fragment->ValidLength),
            (UCHAR const*)virtualAddr->VirtualAddress + fragment->Offset, fragment->ValidLength);

        NetFragmentIteratorAdvance(&fi);
    }

    InterlockedExchangeAddNoFence64(&device->Stats.TunBytesSent, buffer->Len);

    if (device->CryptoContext.Encrypt) {
        // make space to crypto overhead
        OvpnTxBufferPush(buffer, device->CryptoContext.CryptoOverhead);

        // in-place encrypt, always with primary key
        status = device->CryptoContext.Encrypt(&device->CryptoContext.Primary, buffer->Data, buffer->Len);
    }
    else {
        status = STATUS_INVALID_DEVICE_STATE;
        LOG_WARN("CryptoContext not initialized");
    }

    if (NT_SUCCESS(status)) {
        // start async send, this will return ciphertext buffer to the pool
        status = OvpnSocketSend(&device->Socket, buffer);
    }
    else {
        OvpnTxBufferPoolPut(buffer);
    }

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
    bool packetSent = false;

    KIRQL kirql = ExAcquireSpinLockShared(&device->SpinLock);

    while (NetPacketIteratorHasAny(&pi)) {
        NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
        if (!packet->Ignore && !packet->Scratch) {
            NTSTATUS status = OvpnTxSendPacket(device, queue, &pi);
            if (!NT_SUCCESS(status)) {
                InterlockedIncrementNoFence(&device->Stats.LostOutDataPackets);
                break;
            }
            else {
                packetSent = true;
            }
        }

        NetPacketIteratorAdvance(&pi);
    }
    NetPacketIteratorSet(&pi);

    // reset keepalive timer
    if (packetSent) {
        OvpnTimerReset(device->KeepaliveXmitTimer, device->KeepaliveInterval);
    }

    ExReleaseSpinLockShared(&device->SpinLock, kirql);
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
}

_Use_decl_annotations_
VOID
OvpnEvtTxQueueSetNotificationEnabled(NETPACKETQUEUE queue, BOOLEAN notificationEnabled)
{
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(notificationEnabled);
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
