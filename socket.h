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

struct OvpnSocketUdpState
{
	// packet buffer if datagram scattered across MDLs
	// this seems to only happen in unlikely case when datagram is fragmented
	UCHAR PacketBuf[OVPN_SOCKET_RX_PACKET_BUFFER_SIZE];
};

struct OvpnSocket
{
	BOOLEAN Tcp;
	PWSK_SOCKET Socket;

	OvpnSocketTcpState TcpState;
	OvpnSocketUdpState UdpState;
};

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnSocketInit(_In_ WSK_PROVIDER_NPI* wskProviderNpi, _In_ WSK_REGISTRATION* wskRegistration, ADDRESS_FAMILY addrFamily,
	BOOLEAN tcp, _In_ PSOCKADDR localAddr, _In_opt_ PSOCKADDR remoteAddr, SIZE_T remoteAddrSize,
	_In_ PVOID deviceContext, _Out_ PWSK_SOCKET* socket);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnSocketClose(_In_opt_ PWSK_SOCKET socket);

_Must_inspect_result_
NTSTATUS
OvpnSocketSend(_In_ OvpnSocket* ovpnSocket, _In_ OVPN_TX_BUFFER* buffer, _In_opt_ SOCKADDR* sa);

_Must_inspect_result_
NTSTATUS
OvpnSocketTcpConnect(_In_ PWSK_SOCKET socket, _In_ PVOID context, _In_ PSOCKADDR remote);
