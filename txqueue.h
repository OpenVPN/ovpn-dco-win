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

#include "adapter.h"

// The framework runs its one transmit queue on one thread, so only the copy happens
// there: the encryption and the send go to a worker per flow, each with its own core.
#define OVPN_TX_WORKERS_MAX 8

// Buffers a worker may have waiting, per worker. The queue thread stops draining the
// ring once the workers are this far behind, so the pool cannot grow to hold a backlog
// the workers never catch up with.
#define OVPN_TX_QUEUED_MAX_PER_WORKER 256

// Datagrams a worker encrypts before it sends them; see OvpnTxWorkerDpc. With eight
// workers that keeps reordering well inside a 2048-packet replay window.
#define OVPN_TX_SEND_BATCH 128

// Data buffers allowed in flight before the datapath drops rather than grow the pool.
#define OVPN_TX_DATA_INFLIGHT_MAX 2048

// Bytes of TCP data packets sent as one stream write; see OvpnTxSubmit.
#define OVPN_TX_TCP_BATCH_MAX (64 * 1024)

struct OVPN_DEVICE;
struct _OVPN_TXQUEUE;

// Cache aligned: the queue thread writes a worker's list head while the others run, so
// two of them must not share a line.
typedef struct DECLSPEC_CACHEALIGN _OVPN_TX_WORKER
{
    KDPC Dpc;

    // buffers waiting for this worker, threaded through PoolListEntry
    KSPIN_LOCK Lock;
    LIST_ENTRY Queue;

    OVPN_DEVICE* Device;

    // the queue this worker belongs to, for the shared depth count
    struct _OVPN_TXQUEUE* Owner;

    ULONG Index;

    // the processor its dpc runs on
    ULONG Processor;
} OVPN_TX_WORKER, * POVPN_TX_WORKER;

typedef struct _OVPN_TXQUEUE
{
    POVPN_ADAPTER Adapter;

    NET_RING_COLLECTION const * Rings;

    NET_EXTENSION VirtualAddressExtension;

    // zero encrypts and sends on the queue's own thread, as before
    ULONG WorkerCount;

    // buffers handed to workers and not yet taken off their queues
    LONG Queued;

    // set while the framework has stopped polling and waits to be told to resume
    LONG NotificationEnabled;

    OVPN_TX_WORKER Workers[OVPN_TX_WORKERS_MAX];
} OVPN_TXQUEUE, * POVPN_TXQUEUE;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_TXQUEUE, OvpnGetTxQueueContext);

EVT_PACKET_QUEUE_SET_NOTIFICATION_ENABLED OvpnEvtTxQueueSetNotificationEnabled;
EVT_PACKET_QUEUE_ADVANCE OvpnEvtTxQueueAdvance;
EVT_PACKET_QUEUE_CANCEL OvpnEvtTxQueueCancel;

VOID
OvpnTxQueueInitialize(NETPACKETQUEUE txQueue, _In_ POVPN_ADAPTER adapter);

EVT_WDF_OBJECT_CONTEXT_CLEANUP OvpnEvtTxQueueCleanup;
