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

#pragma once

#include <wsk.h>
#include <wdf.h>

#include "bufferpool.h"

struct OvpnSocketTcpState
{
	// filled with 2-bytes length which prepends OpenVPN TCP packet
	UCHAR LenBuf[2];

	USHORT PacketLength;

	// how many bytes already read for header or buffer
	USHORT BytesRead;

	// packet buffer if packet is scattered across MDLs
	UCHAR PacketBuf[OVPN_SOCKET_RX_PACKET_BUFFER_SIZE];
};

// What a send needs. The state buffers below belong to the receive path, and both
// fields here are fixed for the life of a socket.
struct OvpnSocketRef
{
	PWSK_SOCKET Socket;
	BOOLEAN Tcp;
};

struct OvpnSocket
{
	BOOLEAN Tcp;
	PWSK_SOCKET Socket;

	OvpnSocketTcpState TcpState;
};

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnSocketInit(_In_ WSK_PROVIDER_NPI* wskProviderNpi, _In_ WSK_REGISTRATION* wskRegistration, ADDRESS_FAMILY addrFamily,
	BOOLEAN tcp, _In_ PSOCKADDR localAddr, _In_opt_ PSOCKADDR remoteAddr, SIZE_T remoteAddrSize,
	_In_ PVOID deviceContext, _Out_ PWSK_SOCKET* socket, BOOLEAN ipv6only);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnSocketClose(_In_opt_ PWSK_SOCKET socket);

_Must_inspect_result_
NTSTATUS
OvpnSocketSend(_In_ OvpnSocketRef* socket, _In_ OVPN_TX_BUFFER* buffer, _In_opt_ SOCKADDR* sa);

// TCP data: sends a chain of encrypted buffers, linked by WskBufList.Next, as one stream write
VOID
OvpnSocketSendTcpBatch(_In_ OvpnSocketRef* socket, _In_ OVPN_TX_BUFFER* head);

// Rundown for device->Socket: the reference covers the send call, not its completion,
// which is what the device lock gave before. Callers may be at DISPATCH_LEVEL.
struct OVPN_DEVICE;

_Must_inspect_result_
BOOLEAN
OvpnSocketAcquire(_In_ OVPN_DEVICE* device, _When_(return != FALSE, _Out_) OvpnSocketRef* socket);

VOID
OvpnSocketRelease(_In_ OVPN_DEVICE* device);

// Unpublishes the socket, waits for senders already inside one, and returns it to close.
_IRQL_requires_(PASSIVE_LEVEL)
PWSK_SOCKET
OvpnSocketDetach(_In_ OVPN_DEVICE* device);

// Decrypts a received data packet in place. Called by OvpnRxWorkersSubmit's worker.
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
OvpnSocketDataPacketDecrypt(_Inout_ OVPN_RX_BUFFER* buffer);

// The replay check and the rest of receive, for decrypted packets in arrival order, one
// at a time. Takes the buffer and its peer reference.
_IRQL_requires_(DISPATCH_LEVEL)
VOID
OvpnSocketDataPacketDeliver(_In_ OVPN_DEVICE* device, _In_ OVPN_RX_BUFFER* buffer);

_Must_inspect_result_
NTSTATUS
OvpnSocketTcpConnect(_In_ PWSK_SOCKET socket, _In_ PVOID context, _In_ PSOCKADDR remote);

// A peer's remote transport address. It has a name so that the code handling one does
// not have to be a template over a type it cannot spell.
union OVPN_REMOTE_ADDR
{
    SOCKADDR_IN IPv4;
    SOCKADDR_IN6 IPv6;
};

inline
VOID
OvpnSocketCopyRemoteToSockaddr(const OVPN_REMOTE_ADDR& remote, SOCKADDR_STORAGE* sockaddr) {
    // Copy the appropriate address based on the family
    if (remote.IPv4.sin_family == AF_INET) {
        RtlCopyMemory(sockaddr, &remote.IPv4, sizeof(SOCKADDR_IN));
    }
    else if (remote.IPv6.sin6_family == AF_INET6) {
        RtlCopyMemory(sockaddr, &remote.IPv6, sizeof(SOCKADDR_IN6));
    }
}
