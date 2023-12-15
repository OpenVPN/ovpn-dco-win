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

#pragma once

#include <ntddk.h>
#include <wdf.h>

VOID
OvpnTimerReset(WDFTIMER timer, ULONG dueTime);

_Must_inspect_result_
NTSTATUS
OvpnTimerXmitCreate(WDFOBJECT parent, OvpnPeerContext* peer, ULONG period, _Inout_ WDFTIMER* timer);

_Must_inspect_result_
NTSTATUS
OvpnTimerRecvCreate(WDFOBJECT parent, OvpnPeerContext* peer, _Inout_ WDFTIMER* timer);

VOID
OvpnTimerDestroy(_Inout_ WDFTIMER* timer);

_Must_inspect_result_
BOOLEAN
OvpnTimerIsKeepaliveMessage(_In_reads_(len) const PUCHAR buf, SIZE_T len);
