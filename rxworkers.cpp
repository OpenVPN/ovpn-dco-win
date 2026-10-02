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

#include <ntddk.h>
#include <wdf.h>

#include "bufferpool.h"
#include "driver.h"
#include "peer.h"
#include "rxworkers.h"
#include "socket.h"
#include "trace.h"

#define OVPN_RX_SLOT(seq) ((seq) & (OVPN_RX_INFLIGHT_MAX - 1))

// Under workers->Lock
static
BOOLEAN
OvpnRxWorkersHeadReady(_In_ POVPN_RX_WORKERS workers)
{
    return (workers->Head != workers->Next) &&
        ReadAcquire(&workers->Slots[OVPN_RX_SLOT(workers->Head)]->Decrypted);
}

// Deliver decrypted packets from the head, in arrival order, until the head is one still
// being decrypted. Whoever finishes that one delivers it, so nothing waits here.
static
VOID
OvpnRxWorkersDeliver(_Inout_ POVPN_RX_WORKERS workers)
{
    KIRQL irql;
    KeAcquireSpinLock(&workers->Lock, &irql);

    if (workers->Delivering) {
        KeReleaseSpinLock(&workers->Lock, irql);
        return;
    }
    workers->Delivering = TRUE;

    ULONG budget = OVPN_RX_DELIVER_MAX;

    while (budget > 0) {
        LIST_ENTRY ready;
        InitializeListHead(&ready);

        // a worker marks a buffer decrypted before it takes this lock, so one missed here
        // is delivered by that worker once this releases
        while ((budget > 0) && OvpnRxWorkersHeadReady(workers)) {
            OVPN_RX_BUFFER* buffer = workers->Slots[OVPN_RX_SLOT(workers->Head)];
            workers->Slots[OVPN_RX_SLOT(workers->Head)] = NULL;
            ++workers->Head;
            --budget;
            InsertTailList(&ready, &buffer->QueueListEntry);
        }

        if (IsListEmpty(&ready)) {
            break;
        }

        KeReleaseSpinLockFromDpcLevel(&workers->Lock);

        while (!IsListEmpty(&ready)) {
            OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(RemoveHeadList(&ready), OVPN_RX_BUFFER, QueueListEntry);
            OvpnSocketDataPacketDeliver(workers->Device, buffer);
        }

        KeAcquireSpinLockAtDpcLevel(&workers->Lock);
    }

    workers->Delivering = FALSE;

    // out of budget with packets ready: no worker will finish them again, so come back
    BOOLEAN const more = OvpnRxWorkersHeadReady(workers);

    KeReleaseSpinLock(&workers->Lock, irql);

    if (more) {
        KeInsertQueueDpc(&workers->DeliverDpc, NULL, NULL);
    }
}

KDEFERRED_ROUTINE OvpnRxDeliverDpc;

_Use_decl_annotations_
VOID
OvpnRxDeliverDpc(KDPC* dpc, PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    OvpnRxWorkersDeliver((POVPN_RX_WORKERS)context);
}

static
VOID
OvpnRxWorkersDecrypt(_In_ OVPN_RX_BUFFER* buffer)
{
    OvpnSocketDataPacketDecrypt(buffer);

    // delivery may take and free the buffer from here on
    InterlockedExchange(&buffer->Decrypted, TRUE);
}

KDEFERRED_ROUTINE OvpnRxWorkerDpc;

_Use_decl_annotations_
VOID
OvpnRxWorkerDpc(KDPC* dpc, PVOID context, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    POVPN_RX_WORKER worker = (POVPN_RX_WORKER)context;

    // take the whole queue in one go, so the work runs without the lock
    LIST_ENTRY work;
    KeAcquireSpinLockAtDpcLevel(&worker->Lock);
    OvpnListMoveAll(&worker->Queue, &work);
    KeReleaseSpinLockFromDpcLevel(&worker->Lock);

    if (IsListEmpty(&work)) {
        return;
    }

    while (!IsListEmpty(&work)) {
        OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(RemoveHeadList(&work), OVPN_RX_BUFFER, QueueListEntry);
        OvpnRxWorkersDecrypt(buffer);
    }

    OvpnRxWorkersDeliver(worker->Owner);
}

_Use_decl_annotations_
BOOLEAN
OvpnRxWorkersSubmit(POVPN_RX_WORKERS workers, OVPN_RX_BUFFER* buffer)
{
    buffer->Decrypted = FALSE;

    KIRQL irql;
    KeAcquireSpinLock(&workers->Lock, &irql);

    if ((workers->Next - workers->Head) >= OVPN_RX_INFLIGHT_MAX) {
        KeReleaseSpinLock(&workers->Lock, irql);
        return FALSE;
    }

    UINT64 const seq = workers->Next++;
    workers->Slots[OVPN_RX_SLOT(seq)] = buffer;

    KeReleaseSpinLock(&workers->Lock, irql);

    ULONG const workerCount = workers->WorkerCount;
    if (workerCount == 0) {
        OvpnRxWorkersDecrypt(buffer);
        OvpnRxWorkersDeliver(workers);
        return TRUE;
    }

    // not on this core: it is the one the stack receives the tunnel on
    ULONG index = (ULONG)((seq / OVPN_RX_BATCH) % workerCount);
    if (workers->Workers[index].Processor == KeGetCurrentProcessorNumberEx(NULL)) {
        index = (index + 1) % workerCount;
    }
    POVPN_RX_WORKER worker = &workers->Workers[index];

    KeAcquireSpinLock(&worker->Lock, &irql);
    BOOLEAN const wake = IsListEmpty(&worker->Queue);
    InsertTailList(&worker->Queue, &buffer->QueueListEntry);
    KeReleaseSpinLock(&worker->Lock, irql);

    // Once per batch: a worker takes its whole queue, so one that is behind is woken
    // only when it has emptied it. Every packet behind this one waits for it, so the
    // wake cannot be left to a later packet.
    if (wake) {
        KeInsertQueueDpc(&worker->Dpc, NULL, NULL);
    }

    return TRUE;
}

_Use_decl_annotations_
VOID
OvpnRxWorkersInitialize(POVPN_RX_WORKERS workers, OVPN_DEVICE* device)
{
    RtlZeroMemory(workers, sizeof(*workers));

    workers->Device = device;
    KeInitializeSpinLock(&workers->Lock);
    KeInitializeDpc(&workers->DeliverDpc, OvpnRxDeliverDpc, workers);

    ULONG const processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ULONG const count = min(processors, OVPN_RX_WORKERS_MAX);

    if (count < 2) {
        return;
    }

    for (ULONG i = 0; i < count; ++i) {
        POVPN_RX_WORKER worker = &workers->Workers[i];

        worker->Owner = workers;
        KeInitializeSpinLock(&worker->Lock);
        InitializeListHead(&worker->Queue);
        KeInitializeDpc(&worker->Dpc, OvpnRxWorkerDpc, worker);

        // Medium importance would leave a busy target to run it at its next clock tick,
        // and every packet behind it waits that long.
        KeSetImportanceDpc(&worker->Dpc, MediumHighImportance);

        worker->Processor = (i * processors) / count;

        PROCESSOR_NUMBER target;
        if (NT_SUCCESS(KeGetProcessorNumberFromIndex(worker->Processor, &target))) {
            LOG_IF_NOT_NT_SUCCESS(KeSetTargetProcessorDpcEx(&worker->Dpc, &target));
        }
    }

    workers->WorkerCount = count;

    LOG_INFO("Rx workers started", TraceLoggingValue(count, "workers"),
             TraceLoggingValue(processors, "processors"));
}

_Use_decl_annotations_
VOID
OvpnRxWorkersFlush(POVPN_RX_WORKERS workers)
{
    // Every submitted buffer is on a worker whose dpc is queued, or decrypted and waiting
    // for a deliverer that is a dpc. A delivery that yields queues itself again, which one
    // flush may not cover.
    for (;;) {
        KeFlushQueuedDpcs();

        KIRQL irql;
        KeAcquireSpinLock(&workers->Lock, &irql);
        BOOLEAN const done = (workers->Head == workers->Next) && !workers->Delivering;
        KeReleaseSpinLock(&workers->Lock, irql);

        if (done) {
            break;
        }
    }
}

_Use_decl_annotations_
VOID
OvpnRxWorkersStop(POVPN_RX_WORKERS workers)
{
    ULONG const count = InterlockedExchange((LONG*)&workers->WorkerCount, 0);

    for (ULONG i = 0; i < count; ++i) {
        KeRemoveQueueDpc(&workers->Workers[i].Dpc);
    }
    KeRemoveQueueDpc(&workers->DeliverDpc);

    // as for the transmit workers: a dpc already taken off its list is not removed above
    KeFlushQueuedDpcs();

    // nothing is left after a flush, unless a dpc was removed before it ran
    KIRQL irql;
    KeAcquireSpinLock(&workers->Lock, &irql);
    while (workers->Head != workers->Next) {
        OVPN_RX_BUFFER* buffer = workers->Slots[OVPN_RX_SLOT(workers->Head)];
        workers->Slots[OVPN_RX_SLOT(workers->Head)] = NULL;
        ++workers->Head;

        OvpnPeerCtxRelease(buffer->Peer);
        buffer->Peer = NULL;
        OvpnRxBufferPoolPut(buffer);
        InterlockedIncrementNoFence(&workers->Device->Stats.LostInDataPackets);
    }
    KeReleaseSpinLock(&workers->Lock, irql);

    for (ULONG i = 0; i < count; ++i) {
        InitializeListHead(&workers->Workers[i].Queue);
    }
}
