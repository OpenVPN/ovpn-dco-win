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

#include "pktid.h"
#include "driverhelper\trace.h"

#include <wdfcore.h>

/* Warn when packet ID crosses this threshold. */
#define PKTID_WRAP_WARN 0xf0000000ULL

_Use_decl_annotations_
NTSTATUS OvpnPktidXmitNext(OvpnPktidXmit* px, UINT32* pktId)
{
	ULONG64 seqNum = InterlockedIncrementNoFence64(&px->SeqNum);

	*pktId = (UINT32)seqNum;
	if (seqNum < PKTID_WRAP_WARN) {
		return STATUS_SUCCESS;
	}
	else {
		LOG_ERROR("Pktid wrapped");
		return STATUS_INTEGER_OVERFLOW;
	}
}

#define PKTID_RECV_EXPIRE ((30 * WDF_TIMEOUT_TO_SEC) / KeQueryTimeIncrement())

_Use_decl_annotations_
NTSTATUS OvpnPktidRecvVerify(OvpnPktidRecv* pr, UINT32 pktId)
{
	LARGE_INTEGER now;
	KeQueryTickCount(&now);

	/* expire backtracks at or below pr->id after PKTID_RECV_EXPIRE time */
	if ((now.QuadPart - pr->Expire.QuadPart) >= 0)
		pr->IdFloor = pr->Id;

	/* ID must not be zero */
	if (pktId == 0) {
		return STATUS_INVALID_PARAMETER;
	}

	if (pktId == pr->Id + 1) {
		/* well-formed ID sequence (incremented by 1) */
		pr->Base = REPLAY_INDEX(pr->Base, -1);
		pr->History[pr->Base / 8] |= (1 << (pr->Base % 8));
		if (pr->Extent < REPLAY_WINDOW_SIZE)
			++pr->Extent;
		pr->Id = pktId;
	}
	else if (pktId > pr->Id) {
		/* ID jumped forward by more than one */
		UINT32 delta = pktId - pr->Id;

		if (delta < REPLAY_WINDOW_SIZE) {
			pr->Base = REPLAY_INDEX(pr->Base, -(INT32)delta);
			pr->History[pr->Base / 8] |= (1 << (pr->Base % 8));
			pr->Extent += delta;
			if (pr->Extent > REPLAY_WINDOW_SIZE)
				pr->Extent = REPLAY_WINDOW_SIZE;
			for (UINT32 i = 1; i < delta; ++i) {
				unsigned int newb = REPLAY_INDEX(pr->Base, i);

				pr->History[newb / 8] &= ~BIT(newb % 8);
			}
		}
		else {
			pr->Base = 0;
			pr->Extent = REPLAY_WINDOW_SIZE;
			memset(pr->History, 0, sizeof(pr->History));
			pr->History[0] = 1;
		}
		pr->Id = pktId;
	}
	else {
		/* ID backtrack */
		UINT32 delta = pr->Id - pktId;

		if (delta > pr->MaxBacktrack)
			pr->MaxBacktrack = delta;
		if (delta < pr->Extent) {
			if (pktId > pr->IdFloor) {
				UINT32 ri = REPLAY_INDEX(pr->Base, delta);
				PUCHAR p = &pr->History[ri / 8];
				UCHAR mask = (1 << (ri % 8));

				if (*p & mask)
					return STATUS_INVALID_PARAMETER;
				*p |= mask;
			}
			else {
				return STATUS_INVALID_PARAMETER;
			}
		}
		else {
			return STATUS_INVALID_PARAMETER;
		}
	}

	pr->Expire.QuadPart = now.QuadPart + PKTID_RECV_EXPIRE;
	return STATUS_SUCCESS;
}
