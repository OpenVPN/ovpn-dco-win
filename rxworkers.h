/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2026- OpenVPN Inc <sales@openvpn.net>
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

// A tunnel is one UDP flow, so the stack receives all of it on one core. Decryption
// goes to a worker per core; the replay check and delivery stay in arrival order.
#define OVPN_RX_WORKERS_MAX 8

// Packets between the socket and delivery. Past this the socket drops rather than
// wait. A power of two.
#define OVPN_RX_INFLIGHT_MAX 2048

// Consecutive packets go to one worker, so it wakes once for a batch.
#define OVPN_RX_BATCH 16

// Packets one delivery run takes before it yields the core, so a run that keeps finding
// more cannot hold it for good.
#define OVPN_RX_DELIVER_MAX 256

struct OVPN_DEVICE;
struct OVPN_RX_BUFFER;
struct _OVPN_RX_WORKERS;

typedef struct DECLSPEC_CACHEALIGN _OVPN_RX_WORKER
{
    KDPC Dpc;

    // buffers waiting for decryption, threaded through QueueListEntry
    KSPIN_LOCK Lock;
    LIST_ENTRY Queue;

    struct _OVPN_RX_WORKERS* Owner;

    // the processor its dpc runs on
    ULONG Processor;
} OVPN_RX_WORKER, * POVPN_RX_WORKER;

typedef struct _OVPN_RX_WORKERS
{
    OVPN_DEVICE* Device;

    // zero decrypts on the receiving core
    ULONG WorkerCount;

    OVPN_RX_WORKER Workers[OVPN_RX_WORKERS_MAX];

    // continues delivery that yielded with packets still ready
    KDPC DeliverDpc;

    // Every received packet has a slot, by arrival, until delivered. Delivery takes
    // decrypted packets from Head in order, one deliverer at a time, which is also
    // what serializes the replay windows.
    DECLSPEC_CACHEALIGN KSPIN_LOCK Lock;
    UINT64 Next;
    UINT64 Head;
    BOOLEAN Delivering;
    OVPN_RX_BUFFER* Slots[OVPN_RX_INFLIGHT_MAX];
} OVPN_RX_WORKERS, * POVPN_RX_WORKERS;

VOID
OvpnRxWorkersInitialize(_Out_ POVPN_RX_WORKERS workers, _In_ OVPN_DEVICE* device);

// Takes buffer, with its peer reference, for decryption and delivery. FALSE when too
// many packets are in flight; the caller still owns buffer then.
_Must_inspect_result_
BOOLEAN
OvpnRxWorkersSubmit(_Inout_ POVPN_RX_WORKERS workers, _In_ OVPN_RX_BUFFER* buffer);

// Waits until everything submitted so far is delivered. Call once nothing submits.
_IRQL_requires_(PASSIVE_LEVEL)
VOID
OvpnRxWorkersFlush(_Inout_ POVPN_RX_WORKERS workers);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
OvpnRxWorkersStop(_Inout_ POVPN_RX_WORKERS workers);
