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

#include <ntddk.h>

struct OvpnPktidXmit
{
	LONG64 SeqNum;
};

/* replay window sizing in bytes = 2^REPLAY_WINDOW_ORDER */
#define REPLAY_WINDOW_ORDER 8
#define BIT(nr) (1UL << (nr))
#define REPLAY_WINDOW_BYTES BIT(REPLAY_WINDOW_ORDER)
#define REPLAY_WINDOW_SIZE (REPLAY_WINDOW_BYTES * 8)
#define REPLAY_INDEX(base, i) (((base) + (i)) & (REPLAY_WINDOW_SIZE - 1))

struct OvpnPktidRecv
{
	/* "sliding window" bitmask of recent packet IDs received */
	UCHAR History[REPLAY_WINDOW_BYTES];

	/* bit position of deque base in history */
	UINT32 Base;

	/* extent (in bits) of deque in history */
	UINT32 Extent;

	/* expiration of history in count of timer interrupts */
	LARGE_INTEGER Expire;

	/* highest sequence number received */
	UINT64 Id;

	/* we will only accept backtrack IDs > id_floor */
	UINT64 IdFloor;
};

/* Get the next packet ID for xmit */
NTSTATUS OvpnPktidXmitNext(_In_ OvpnPktidXmit* px, _Out_ VOID* pktId, BOOLEAN pktId64bit);


/* Packet replay detection.
 * Allows ID backtrack of up to REPLAY_WINDOW_SIZE - 1.
 */
NTSTATUS OvpnPktidRecvVerify(_In_ OvpnPktidRecv* pid, UINT64 pktId);
