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

_Must_inspect_result_
static
NTSTATUS
OvpnTxProcessPacket(_In_ POVPN_DEVICE device, _In_ POVPN_TXQUEUE queue, _In_ NET_RING_PACKET_ITERATOR *pi,
    _Inout_ OVPN_TX_BUFFER **head, _Inout_ OVPN_TX_BUFFER** tail, _Inout_ SOCKADDR_STORAGE *headSockaddr)
{
    NET_RING_FRAGMENT_ITERATOR fi = NetPacketIteratorGetFragments(pi);

    OvpnPeerContext* peer = NULL;

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

        RtlCopyMemory(OvpnBufferPut(buffer, fragment->ValidLength),
            (UCHAR const*)virtualAddr->VirtualAddress + fragment->Offset, fragment->ValidLength);

        NetFragmentIteratorAdvance(&fi);
    }

    if (OvpnMssIsIPv4(buffer->Data, buffer->Len)) {
        auto addr = ((IPV4_HEADER*)buffer->Data)->DestinationAddress;

        peer = OvpnFindPeerVPN4(device, addr, FALSE);
        if (peer == nullptr) {
            peer = device->IRoutesIPV4.Find(reinterpret_cast<UCHAR*>(&addr));
        }

        if ((device->Mode == OVPN_MODE_P2P) && (peer != nullptr) && (OvpnCheckRecursiveRoutingIPv4(&peer->TransportAddrs.Remote.IPv4, buffer->Data, buffer->Len, device->Socket.Tcp))) {
            OvpnPeerCtxRelease(peer);
            peer = nullptr;
        }

        if (peer != nullptr) {
            OvpnMssDoIPv4(buffer->Data, buffer->Len, peer->MSS);
        }
    } else if (OvpnMssIsIPv6(buffer->Data, buffer->Len)) {
        auto addr = ((IPV6_HEADER*)buffer->Data)->DestinationAddress;

        peer = OvpnFindPeerVPN6(device, addr, FALSE);
        if (peer == nullptr) {
            peer = device->IRoutesIPV6.Find(reinterpret_cast<UCHAR*>(&addr));
        }

        if ((device->Mode == OVPN_MODE_P2P) && (peer != nullptr) && (OvpnCheckRecursiveRoutingIPv6(&peer->TransportAddrs.Remote.IPv6, buffer->Data, buffer->Len, device->Socket.Tcp))) {
            OvpnPeerCtxRelease(peer);
            peer = nullptr;
        }

        if (peer != nullptr) {
            OvpnMssDoIPv6(buffer->Data, buffer->Len, peer->MSS);
        }
    }

    if (peer == nullptr) {
        status = STATUS_ADDRESS_NOT_ASSOCIATED;
        OvpnTxBufferPoolPut(buffer);
        goto out;
    }

    InterlockedExchangeAddNoFence64(&device->Stats.TunBytesSent, buffer->Len);
    InterlockedExchangeAddNoFence64(&peer->VpnTxBytes, buffer->Len);

    auto irql = ExAcquireSpinLockShared(&peer->SpinLock);

    OvpnCryptoContext* cryptoContext = &peer->CryptoContext;
    auto remoteAddr = peer->TransportAddrs.Remote;

    if (cryptoContext->Encrypt) {
        auto aeadTagEnd = cryptoContext->CryptoOptions & CRYPTO_OPTIONS_AEAD_TAG_END;
        auto pktId64bit = cryptoContext->CryptoOptions & CRYPTO_OPTIONS_64BIT_PKTID;

        // make space to crypto overhead
        OvpnTxBufferPush(buffer, OVPN_DATA_V2_LEN + (pktId64bit ? 8 : 4) + (aeadTagEnd ? 0 : AEAD_AUTH_TAG_LEN));
        if (aeadTagEnd)
        {
            OvpnBufferPut(buffer, AEAD_AUTH_TAG_LEN);
        }

        // in-place encrypt, always with primary key
        status = cryptoContext->Encrypt(&cryptoContext->Primary, buffer->Data, buffer->Len, cryptoContext->CryptoOptions);
    }
    else {
        status = STATUS_INVALID_DEVICE_STATE;
        // LOG_WARN("CryptoContext not initialized");
    }
    ExReleaseSpinLockShared(&peer->SpinLock, irql);

    if (NT_SUCCESS(status)) {
        InterlockedExchangeAddNoFence64(&peer->LinkTxBytes, buffer->Len);

        // start async send, this will return ciphertext buffer to the pool
        if (device->Socket.Tcp) {
            status = OvpnSocketSend(&device->Socket, buffer, NULL);
        }
        else {
            // for UDP we use SendMessages to send multiple datagrams at once
            // here we only append WSK_BUF to the list

            buffer->WskBufList.Buffer.Length = buffer->Len;
            buffer->WskBufList.Buffer.Mdl = buffer->Mdl;
            buffer->WskBufList.Buffer.Offset = FIELD_OFFSET(OVPN_TX_BUFFER, Head) + (ULONG)(buffer->Data - buffer->Head);

            // If this peer is different (head sockaddr != peer sockaddr) to the previous buffer chain peers,
            // then flush those and restart with a new buffer list.

            if ((*head != NULL) && !(OvpnTxAreSockaddrEqual((const SOCKADDR*)headSockaddr, (const SOCKADDR*)&remoteAddr)))
            {
                LOG_IF_NOT_NT_SUCCESS(OvpnSocketSend(&device->Socket, *head, (SOCKADDR*)headSockaddr));
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
        }

        OvpnTimerResetXmit(peer->Timer);
    }
    else {
        OvpnTxBufferPoolPut(buffer);
    }

    if (peer != nullptr) {
        OvpnPeerCtxRelease(peer);
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
    BOOLEAN isTcp = device->Socket.Tcp;
    ExReleaseSpinLockShared(&device->SpinLock, kirql);

    OVPN_TX_BUFFER* txBufferHead = NULL;
    OVPN_TX_BUFFER* txBufferTail = NULL;
    SOCKADDR_STORAGE headSockaddr = {0};

    while (NetPacketIteratorHasAny(&pi)) {
        NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
        NTSTATUS status = STATUS_SUCCESS;
        if (!packet->Ignore && !packet->Scratch) {
            status = OvpnTxProcessPacket(device, queue, &pi, &txBufferHead, &txBufferTail, &headSockaddr);
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
        LOG_IF_NOT_NT_SUCCESS(OvpnSocketSend(&device->Socket, txBufferHead, (SOCKADDR*)&headSockaddr));
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
