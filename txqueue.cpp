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

_Must_inspect_result_
_Requires_shared_lock_held_(device->SpinLock)
static
NTSTATUS
OvpnTxProcessPacket(_In_ POVPN_DEVICE device, _In_ POVPN_TXQUEUE queue, _In_ NET_RING_PACKET_ITERATOR *pi,
    _Inout_ OVPN_TX_BUFFER **head, _Inout_ OVPN_TX_BUFFER** tail)
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

        RtlCopyMemory(OvpnTxBufferPut(buffer, fragment->ValidLength),
            (UCHAR const*)virtualAddr->VirtualAddress + fragment->Offset, fragment->ValidLength);

        NetFragmentIteratorAdvance(&fi);
    }

    if (OvpnMssIsIPv4(buffer->Data, buffer->Len)) {
        OvpnMssDoIPv4(buffer->Data, buffer->Len, device->MSS);
    } else if (OvpnMssIsIPv6(buffer->Data, buffer->Len)) {
        OvpnMssDoIPv6(buffer->Data, buffer->Len, device->MSS);
    }

    OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);
    if (peer == NULL) {
        status = STATUS_ADDRESS_NOT_ASSOCIATED;
        OvpnTxBufferPoolPut(buffer);
        LOG_WARN("No peer");
        goto out;
    }

    InterlockedExchangeAddNoFence64(&device->Stats.TunBytesSent, buffer->Len);

    OvpnCryptoContext* cryptoContext = &peer->CryptoContext;

    if (cryptoContext->Encrypt) {
        auto aeadTagEnd = cryptoContext->CryptoOptions & CRYPTO_OPTIONS_AEAD_TAG_END;
        auto pktId64bit = cryptoContext->CryptoOptions & CRYPTO_OPTIONS_64BIT_PKTID;

        // make space to crypto overhead
        OvpnTxBufferPush(buffer, OVPN_DATA_V2_LEN + (pktId64bit ? 8 : 4) + (aeadTagEnd ? 0 : AEAD_AUTH_TAG_LEN));
        if (aeadTagEnd)
        {
            OvpnTxBufferPut(buffer, AEAD_AUTH_TAG_LEN);
        }

        // in-place encrypt, always with primary key
        status = cryptoContext->Encrypt(&cryptoContext->Primary, buffer->Data, buffer->Len, cryptoContext->CryptoOptions);
    }
    else {
        status = STATUS_INVALID_DEVICE_STATE;
        // LOG_WARN("CryptoContext not initialized");
    }

    if (NT_SUCCESS(status)) {
        // start async send, this will return ciphertext buffer to the pool
        if (device->Socket.Tcp) {
            status = OvpnSocketSend(&device->Socket, buffer);
        }
        else {
            // for UDP we use SendMessages to send multiple datagrams at once
            // here we only append WSK_BUF to the list

            buffer->WskBufList.Buffer.Length = buffer->Len;
            buffer->WskBufList.Buffer.Mdl = buffer->Mdl;
            buffer->WskBufList.Buffer.Offset = FIELD_OFFSET(OVPN_TX_BUFFER, Head) + (ULONG)(buffer->Data - buffer->Head);

            if (*head == NULL) {
                *head = buffer;
            }
            else {
                (*tail)->WskBufList.Next = &buffer->WskBufList;
            }

            *tail = buffer;
        }

        OvpnTimerResetXmit(peer->Timer);
    }
    else {
        OvpnTxBufferPoolPut(buffer);
    }

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

    KIRQL kirql = ExAcquireSpinLockShared(&device->SpinLock);

    OVPN_TX_BUFFER* txBufferHead = NULL;
    OVPN_TX_BUFFER* txBufferTail = NULL;

    while (NetPacketIteratorHasAny(&pi)) {
        NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
        NTSTATUS status = STATUS_SUCCESS;
        if (!packet->Ignore && !packet->Scratch) {
            status = OvpnTxProcessPacket(device, queue, &pi, &txBufferHead, &txBufferTail);
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

    if (packetSent) {
        OvpnPeerContext* peer = OvpnGetFirstPeer(&device->Peers);
        if (peer != NULL) {
            OvpnTimerResetXmit(peer->Timer);

            if (!device->Socket.Tcp) {
                // this will use WskSendMessages to send buffers list which we constructed before
                LOG_IF_NOT_NT_SUCCESS(OvpnSocketSend(&device->Socket, txBufferHead));
            }
        }
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
