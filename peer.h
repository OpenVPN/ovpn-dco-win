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

#include "driver.h"
#include "uapi\ovpn-dco.h"

struct OvpnPeerContext
{
    OvpnCryptoContext CryptoContext;

    INT32 PeerId;

    // keepalive interval in seconds
    LONG KeepaliveInterval;

    // keepalive timeout in seconds
    LONG KeepaliveTimeout;

    // 1-sec timer which handles ping intervals and keepalive timeouts
    WDFTIMER Timer;
};

_Must_inspect_result_
OvpnPeerContext*
OvpnPeerCtxAlloc();

VOID
OvpnPeerCtxFree(_In_ OvpnPeerContext*);

RTL_GENERIC_ALLOCATE_ROUTINE OvpnPeerAllocateRoutine;
RTL_GENERIC_FREE_ROUTINE OvpnPeerFreeRoutine;
RTL_GENERIC_COMPARE_ROUTINE OvpnPeerCompareByPeerIdRoutine;

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnPeerNew(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnPeerDel(_In_ POVPN_DEVICE device);

_Must_inspect_result_
_Requires_exclusive_lock_held_(device->SpinLock)
NTSTATUS
OvpnPeerSet(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
NTSTATUS
_Requires_shared_lock_held_(device->SpinLock)
OvpnPeerGetStats(_In_ POVPN_DEVICE device, WDFREQUEST request, _Out_ ULONG_PTR* bytesReturned);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
OvpnPeerStartVPN(_In_ POVPN_DEVICE device);

_Must_inspect_result_
_Requires_exclusive_lock_held_(device->SpinLock)
NTSTATUS
OvpnPeerNewKey(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
_Requires_exclusive_lock_held_(device->SpinLock)
NTSTATUS
OvpnPeerNewKeyV2(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
_Requires_exclusive_lock_held_(device->SpinLock)
NTSTATUS
OvpnPeerSwapKeys(_In_ POVPN_DEVICE device);
