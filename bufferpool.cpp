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

#include <wdm.h>

#include "bufferpool.h"
#include "trace.h"

#define OVPN_BUFFER_HEADROOM 256

struct OVPN_BUFFER_POOL_IMPL
{
    LIST_ENTRY ListHead;
    KSPIN_LOCK Lock;
    UINT32 ItemSize;
    VOID* Context;
    UCHAR* Mem;
};

struct OVPN_BUFFER_QUEUE_IMPL
{
    LIST_ENTRY ListHead;
    KSPIN_LOCK Lock;
};

NTSTATUS
OvpnBufferQueueCreate(OVPN_BUFFER_QUEUE* handle)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OVPN_BUFFER_QUEUE_IMPL), 'ovpn');
    if (!queue)
        return STATUS_MEMORY_NOT_ALLOCATED;

    InitializeListHead(&queue->ListHead);
    KeInitializeSpinLock(&queue->Lock);

    *handle = (OVPN_BUFFER_QUEUE)queue;
    return STATUS_SUCCESS;
}

VOID
OvpnBufferQueueEnqueue(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    ExInterlockedInsertTailList(&queue->ListHead, listEntry, &queue->Lock);
}

VOID
OvpnBufferQueueEnqueueHead(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    ExInterlockedInsertHeadList(&queue->ListHead, listEntry, &queue->Lock);
}

LIST_ENTRY*
OvpnBufferQueueDequeue(OVPN_BUFFER_QUEUE handle)
{
    LIST_ENTRY* entry = NULL;
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    entry = ExInterlockedRemoveHeadList(&queue->ListHead, &queue->Lock);

    return entry;
}

static
NTSTATUS
OvpnBufferPoolCreate(OVPN_BUFFER_POOL* handle, UINT32 itemSize, UINT32 itemsCount, VOID* ctx)
{
    NTSTATUS status = STATUS_SUCCESS;
    *handle = NULL;
    OVPN_BUFFER_POOL_IMPL* pool = NULL;

    pool = (OVPN_BUFFER_POOL_IMPL*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OVPN_BUFFER_POOL_IMPL), 'ovpn');
    if (!pool) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto error;
    }

    InitializeListHead(&pool->ListHead);
    KeInitializeSpinLock(&pool->Lock);

    pool->Mem = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, itemsCount * (sizeof(LIST_ENTRY) + itemSize), 'ovpn');
    if (!pool->Mem) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto error;
    }

    for (UINT32 i = 0; i < itemsCount; ++i) {
        LIST_ENTRY* entry = (LIST_ENTRY*)(pool->Mem + ((sizeof(LIST_ENTRY) + itemSize) * i));
        ExInterlockedInsertTailList(&pool->ListHead, entry, &pool->Lock);
    }

    *handle = (OVPN_BUFFER_POOL)pool;

    pool->ItemSize = itemSize;

    pool->Context = ctx;

    goto done;

error:
    if (pool) {
        if (pool->Mem)
            ExFreePoolWithTag(pool->Mem, 'ovpn');

        ExFreePoolWithTag(pool, 'ovpn');
    }

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnTxBufferPoolCreate(OVPN_TX_BUFFER_POOL* handle, VOID* ctx)
{
    return OvpnBufferPoolCreate((OVPN_BUFFER_POOL*)handle, sizeof(OVPN_TX_BUFFER) + OVPN_SOCKET_PACKET_BUFFER_SIZE, 1024, ctx);
}

VOID*
OvpnTxBufferPoolGetContext(OVPN_TX_BUFFER_POOL handle)
{
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;
    return pool->Context;
}

static
VOID*
OvpnBufferPoolGet(OVPN_BUFFER_POOL handle) {
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;
    LIST_ENTRY* entry = NULL;

    entry = ExInterlockedRemoveHeadList(&pool->ListHead, &pool->Lock);

    if (entry != NULL) {
        UCHAR* buf = (UCHAR*)entry + sizeof(LIST_ENTRY);
        return buf;
    }
    else
        return NULL;
}

_Use_decl_annotations_
NTSTATUS
OvpnTxBufferPoolGet(OVPN_TX_BUFFER_POOL handle, OVPN_TX_BUFFER** buffer)
{
    VOID* buf = OvpnBufferPoolGet((OVPN_BUFFER_POOL)handle);
    if (buf == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    *buffer = (OVPN_TX_BUFFER*)buf;
    (*buffer)->Mdl = IoAllocateMdl(*buffer, sizeof(OVPN_TX_BUFFER) + OVPN_SOCKET_PACKET_BUFFER_SIZE, FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool((*buffer)->Mdl);

    (*buffer)->Pool = handle;

    (*buffer)->Data = (*buffer)->Head + OVPN_BUFFER_HEADROOM;
    (*buffer)->Tail = (*buffer)->Data;

    (*buffer)->Len = 0;

    (*buffer)->IoQueue = WDF_NO_HANDLE;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnRxBufferPoolGet(OVPN_RX_BUFFER_POOL handle, OVPN_RX_BUFFER** buffer)
{
    VOID* buf = OvpnBufferPoolGet((OVPN_BUFFER_POOL)handle);
    if (buf == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    *buffer = (OVPN_RX_BUFFER*)buf;

    (*buffer)->Pool = handle;
    (*buffer)->Len = 0;

    return STATUS_SUCCESS;
}

static
VOID
OvpnBufferPoolPut(OVPN_BUFFER_POOL handle, VOID* data)
{
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;

    LIST_ENTRY* entry = (LIST_ENTRY*)((PUCHAR)data - sizeof(LIST_ENTRY));
    ExInterlockedInsertTailList(&pool->ListHead, entry, &pool->Lock);
}

_Use_decl_annotations_
VOID
OvpnTxBufferPoolPut(OVPN_TX_BUFFER* buffer)
{
    IoFreeMdl(buffer->Mdl);

    OvpnBufferPoolPut((OVPN_BUFFER_POOL)buffer->Pool, buffer);
}

_Use_decl_annotations_
VOID
OvpnRxBufferPoolPut(_In_ OVPN_RX_BUFFER* buffer)
{
    OvpnBufferPoolPut((OVPN_BUFFER_POOL)buffer->Pool, &buffer->ListEntry);
}

VOID
OvpnBufferPoolDelete(OVPN_BUFFER_POOL handle)
{
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;

    if (pool->Mem)
        ExFreePoolWithTag(pool->Mem, 'ovpn');

    ExFreePoolWithTag(pool, 'ovpn');
}

_Use_decl_annotations_
UCHAR*
OvpnTxBufferPut(OVPN_TX_BUFFER* buffer, SIZE_T len)
{
    UCHAR* tmp = buffer->Tail;
    buffer->Tail += len;
    buffer->Len += len;

    return tmp;
}

_Use_decl_annotations_
UCHAR*
OvpnTxBufferPush(OVPN_TX_BUFFER* buffer, SIZE_T len)
{
    buffer->Data -= len;
    buffer->Len += len;

    return buffer->Data;
}

_Use_decl_annotations_
NTSTATUS
OvpnRxBufferPoolCreate(OVPN_RX_BUFFER_POOL* handle)
{
    return OvpnBufferPoolCreate((OVPN_BUFFER_POOL*)handle, sizeof(OVPN_RX_BUFFER), 1024, NULL);
}

VOID
OvpnBufferQueueDelete(OVPN_BUFFER_QUEUE handle)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    ExFreePoolWithTag(queue, 'ovpn');
}