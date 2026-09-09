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
    LIST_ENTRY ListEntry; // used by iroute tries for deferred cleanup

    EX_SPIN_LOCK SpinLock;

    OvpnCryptoContext CryptoContext;

    INT32 PeerId;

    // keepalive interval in seconds
    LONG KeepaliveInterval;

    // keepalive timeout in seconds
    LONG KeepaliveTimeout;

    // 1-sec timer which handles ping intervals and keepalive timeouts
    WDFTIMER Timer;

    // pre-created work item used to defer OvpnPeerCtxFree() to PASSIVE_LEVEL
    // when the last reference is dropped at DISPATCH_LEVEL, so the timer can be
    // stopped synchronously (draining any running tick) before the peer is freed
    WDFWORKITEM CleanupWorkItem;

    UINT16 MSS;

    struct {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } VpnAddrs;

    struct {
        union {
            SOCKADDR_IN IPv4;
            SOCKADDR_IN6 IPv6;
        } Remote;

    } TransportAddrs;

    LONG RefCounter;

    LONG64 LinkRxBytes;
    LONG64 LinkTxBytes;
    LONG64 VpnRxBytes;
    LONG64 VpnTxBytes;
};

_Must_inspect_result_
OvpnPeerContext*
OvpnPeerCtxAlloc(_In_ WDFDEVICE device);

VOID
OvpnPeerCtxFree(_In_ OvpnPeerContext*);

VOID
OvpnPeerCtxRelease(_In_ OvpnPeerContext*);

RTL_GENERIC_ALLOCATE_ROUTINE OvpnPeerAllocateRoutine;
RTL_GENERIC_FREE_ROUTINE OvpnPeerFreeRoutine;
RTL_GENERIC_COMPARE_ROUTINE OvpnPeerCompareByPeerIdRoutine;
RTL_GENERIC_COMPARE_ROUTINE OvpnPeerCompareByVPN4Routine;
RTL_GENERIC_COMPARE_ROUTINE OvpnPeerCompareByVPN6Routine;
RTL_GENERIC_COMPARE_ROUTINE OvpnPeerCompareByTransportRoutine;

_Must_inspect_result_
NTSTATUS
OvpnAddPeerToTable(POVPN_DEVICE device, _In_ RTL_GENERIC_TABLE* table, _In_ OvpnPeerContext* peer);

VOID
OvpnCleanupPeerTable(_In_ POVPN_DEVICE device, _In_ RTL_GENERIC_TABLE*);

_Must_inspect_result_
OvpnPeerContext*
OvpnGetFirstPeer(_In_ POVPN_DEVICE device);

_Must_inspect_result_
OvpnPeerContext*
OvpnFindPeer(_In_ POVPN_DEVICE device, INT32 PeerId, BOOLEAN dpc);

_Must_inspect_result_
OvpnPeerContext*
OvpnFindPeerVPN4(_In_ POVPN_DEVICE device, _In_ IN_ADDR addr, BOOLEAN dpc);

_Must_inspect_result_
OvpnPeerContext*
OvpnFindPeerVPN6(_In_ POVPN_DEVICE device, _In_ IN6_ADDR addr, BOOLEAN dpc);

_Must_inspect_result_
OvpnPeerContext*
OvpnFindPeerTransport(_In_ POVPN_DEVICE device, _In_ PSOCKADDR sa, BOOLEAN dpc);

VOID
OvpnDeletePeerFromTable(POVPN_DEVICE device, RTL_GENERIC_TABLE* table, OvpnPeerContext* peer, char* tableName);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnPeerNew(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
OvpnMPPeerNew(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
_Requires_exclusive_lock_held_(device->SpinLock)
NTSTATUS
OvpnPeerSet(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
_Requires_exclusive_lock_held_(device->SpinLock)
NTSTATUS
OvpnMPPeerSet(_In_ POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
NTSTATUS
_Requires_shared_lock_held_(device->SpinLock)
OvpnPeerGetStats(_In_ POVPN_DEVICE device, WDFREQUEST request, _Out_ ULONG_PTR* bytesReturned);

_Must_inspect_result_
NTSTATUS
OvpnPeerGetStatsV2(_In_ POVPN_DEVICE device, WDFREQUEST request, _Out_ ULONG_PTR* bytesReturned);

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
NTSTATUS
OvpnPeerSwapKeys(_In_ POVPN_DEVICE device);

_Must_inspect_result_
NTSTATUS
OvpnPeerDelete(POVPN_DEVICE device, INT32 peerId, OVPN_DEL_PEER_REASON reason, BOOLEAN notify);

_Must_inspect_result_
NTSTATUS
OvpnMPPeerDelete(POVPN_DEVICE device, WDFREQUEST request);

_Must_inspect_result_
NTSTATUS
OvpnMPPeerSwapKeys(_In_ POVPN_DEVICE device, WDFREQUEST request);

PCCH
OvpnPeerGetDelReasonString(OVPN_DEL_PEER_REASON reason);

NTSTATUS
OvpnPeerHandleFloat(OVPN_DEVICE* device, OvpnPeerContext* peer, PSOCKADDR sa, BOOLEAN dpc);

static inline KIRQL
OvpnAcquireSpinLock(BOOLEAN dpc, PEX_SPIN_LOCK spinLock, BOOLEAN exclusive)
{
    KIRQL kirql = 0;
    if (dpc) {
        if (exclusive) {
            ExAcquireSpinLockExclusiveAtDpcLevel(spinLock);
        }
        else {
            ExAcquireSpinLockSharedAtDpcLevel(spinLock);
        }
    }
    else {
        if (exclusive) {
            kirql = ExAcquireSpinLockExclusive(spinLock);
        }
        else {
            kirql = ExAcquireSpinLockShared(spinLock);
        }
    }

    return kirql;
}

static inline VOID
OvpnReleaseSpinLock(BOOLEAN dpc, KIRQL kirql, PEX_SPIN_LOCK spinLock, BOOLEAN exclusive)
{
    if (dpc) {
        if (exclusive) {
            ExReleaseSpinLockExclusiveFromDpcLevel(spinLock);
        }
        else {
            ExReleaseSpinLockSharedFromDpcLevel(spinLock);
        }
    }
    else {
        if (exclusive) {
            ExReleaseSpinLockExclusive(spinLock, kirql);
        }
        else {
            ExReleaseSpinLockShared(spinLock, kirql);
        }
    }
}
