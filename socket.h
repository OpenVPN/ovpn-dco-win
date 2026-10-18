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

struct OVPN_DEVICE;

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

struct OvpnSocket
{
	// the device this socket belongs to: WSK hands this object to the receive
	// callbacks, which reach everything else through here
	OVPN_DEVICE* Device;

	BOOLEAN Tcp;
	PWSK_SOCKET Socket;

	OvpnSocketTcpState TcpState;

	// What keeps this socket open: the device's slot while it is the current one, and
	// every peer that sends over it. The last holder to let go closes it, so nothing
	// has to wait for a send or a connect to finish before tearing a session down.
	volatile LONG Refs;

	// Closing needs PASSIVE_LEVEL and the last reference can go at DISPATCH_LEVEL.
	// Deliberately not a WDFWORKITEM: the device's own children are disposed while its
	// cleanup runs, and that cleanup is what waits for this to close the socket.
	PIO_WORKITEM CloseWorkItem;

	// Set when the device lets go of it. A retired socket stays open while someone
	// is still sending over it, but what it receives is no longer anyone's: the
	// session it belonged to is gone.
	volatile LONG Retired;
};

// Creates a socket and its WSK handle, with one reference for the caller.
_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnSocketCreate(_In_ OVPN_DEVICE* device, ADDRESS_FAMILY addrFamily, BOOLEAN tcp,
	_In_ PSOCKADDR localAddr, _In_opt_ PSOCKADDR remoteAddr, SIZE_T remoteAddrSize,
	BOOLEAN ipv6only, _Outptr_ OvpnSocket** sock);

// One more holder of the socket. Callers may be at DISPATCH_LEVEL.
VOID
OvpnSocketReference(_In_ OvpnSocket* sock);

// One fewer holder. The last one closes the socket and frees it, from a work item when
// it has to. Callers may be at DISPATCH_LEVEL.
VOID
OvpnSocketRelease(_In_opt_ OvpnSocket* sock);

// The same, for callers that must not be kept waiting even at PASSIVE_LEVEL: the close
// always goes to the work item. For the datapath, which owes NetAdapterCx a prompt
// return and cannot spend it inside a WSK close.
VOID
OvpnSocketReleaseNoBlock(_In_opt_ OvpnSocket* sock);

// The device's current socket with a reference on it, or NULL when it has none. For
// the paths that have no peer to take it from.
_Must_inspect_result_
OvpnSocket*
OvpnSocketGet(_In_ OVPN_DEVICE* device);

// Makes this the device's current socket, letting go of the one it had. NULL for a
// session that is going away.
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
OvpnSocketPublish(_In_ OVPN_DEVICE* device, _In_opt_ OvpnSocket* sock);

_Must_inspect_result_
NTSTATUS
OvpnSocketSend(_In_ OvpnSocket* sock, _In_ OVPN_TX_BUFFER* buffer, _In_opt_ SOCKADDR* sa);

// TCP data: sends a chain of encrypted buffers, linked by WskBufList.Next, as one stream write
VOID
OvpnSocketSendTcpBatch(_In_ OvpnSocket* sock, _In_ OVPN_TX_BUFFER* head);

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
OvpnSocketTcpConnect(_In_ OvpnSocket* sock, _In_ PSOCKADDR remote);

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
