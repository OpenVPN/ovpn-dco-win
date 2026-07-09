/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2024- OpenVPN Inc <sales@openvpn.net>
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

#if defined(_KERNEL_MODE)
#include <ntddk.h>
#include "uapi/ovpn-dco.h"
#else
/* uapi/ovpn-dco.h pulls <winsock2.h> first so it must precede <windows.h>,
 * otherwise windows.h brings in the legacy <winsock.h> and the two collide. */
#include "uapi/ovpn-dco.h"
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#endif

/*
 * Fill one OVPN_PEER_STATS record. The buffer aliases a METHOD_BUFFERED
 * system buffer that the I/O Manager does NOT zero, and OVPN_PEER_STATS has a
 * 4-byte alignment hole between PeerId and LinkRxBytes. Zeroing first is what
 * keeps that hole (and any tail residue) from leaking non-paged pool to user
 * mode -- do not drop it. Both OvpnPeerGetStats paths funnel through here so
 * the zero can't be forgotten in one of them.
 */
__inline void
OvpnFillPeerStats(OVPN_PEER_STATS* out, INT32 peerId,
    LONG64 linkRxBytes, LONG64 linkTxBytes, LONG64 vpnRxBytes, LONG64 vpnTxBytes)
{
    RtlZeroMemory(out, sizeof(*out));
    out->PeerId = peerId;
    out->LinkRxBytes = linkRxBytes;
    out->LinkTxBytes = linkTxBytes;
    out->VpnRxBytes = vpnRxBytes;
    out->VpnTxBytes = vpnTxBytes;
}
