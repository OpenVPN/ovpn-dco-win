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

#include "adapter.h"
#include "bufferpool.h"
#include "trace.h"

#define OVPN_BUFFER_HEADROOM 26 // we prepend TCP packet size (2 bytes) and crypto overhead (24 bytes)

// good enough limit for in-flight packets
constexpr auto MAX_POOL_SIZE = 100'000;

struct OVPN_BUFFER_POOL_IMPL
{
    LIST_ENTRY ListHead;
    KSPIN_LOCK Lock;
    UINT32 ItemSize;
    LONG PoolSize;
    VOID* Context;
    CHAR* Tag;
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
OvpnBufferPoolCreate(OVPN_BUFFER_POOL* handle, UINT32 itemSize, CHAR* tag, VOID* ctx)
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

    *handle = (OVPN_BUFFER_POOL)pool;

    pool->ItemSize = itemSize;
    pool->Tag = tag;
    pool->Context = ctx;

    goto done;

error:
    if (pool) {
        ExFreePoolWithTag(pool, 'ovpn');
        pool = NULL;
    }

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnTxBufferPoolCreate(OVPN_TX_BUFFER_POOL* handle, VOID* ctx)
{
    return OvpnBufferPoolCreate((OVPN_BUFFER_POOL*)handle, sizeof(OVPN_TX_BUFFER) + OVPN_DCO_MTU_MAX + OVPN_BUFFER_HEADROOM, "tx", ctx);
}

VOID*
OvpnTxBufferPoolGetContext(OVPN_TX_BUFFER_POOL handle)
{
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;
    return pool->Context;
}

template<class POOL_ENTRY>
static
VOID
OvpnBufferPoolGet(OVPN_BUFFER_POOL handle, POOL_ENTRY** entry) {
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;

    LIST_ENTRY* slist_entry = ExInterlockedRemoveHeadList(&pool->ListHead, &pool->Lock);
    if (slist_entry) {
        *entry = CONTAINING_RECORD(slist_entry, POOL_ENTRY, PoolListEntry);
    } else {
        if (pool->PoolSize > MAX_POOL_SIZE)
        {
            *entry = NULL;
            LOG_ERROR("Pool size is too large", TraceLoggingValue(pool->Tag, "tag"), TraceLoggingValue(pool->PoolSize, "size"));
            return;
        }
        *entry = (POOL_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, pool->ItemSize, 'ovpn');
        if (*entry)
        {
            InterlockedIncrement(&pool->PoolSize);
            if ((pool->PoolSize % 256) == 0) {
                LOG_INFO("Pool size", TraceLoggingValue(pool->Tag, "tag"), TraceLoggingValue(pool->PoolSize, "size"));
            }
        }
    }
}

_Use_decl_annotations_
NTSTATUS
OvpnTxBufferPoolGet(OVPN_TX_BUFFER_POOL handle, OVPN_TX_BUFFER** buffer)
{
    OvpnBufferPoolGet((OVPN_BUFFER_POOL)handle, buffer);
    if (*buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    (*buffer)->Pool = handle;

    (*buffer)->Mdl = IoAllocateMdl(*buffer, ((OVPN_BUFFER_POOL_IMPL*)handle)->ItemSize, FALSE, FALSE, NULL);
    if (((*buffer)->Mdl) == NULL)
    {
        OvpnTxBufferPoolPut(*buffer);
        *buffer = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool((*buffer)->Mdl);

    (*buffer)->Data = (*buffer)->Head + OVPN_BUFFER_HEADROOM;
    (*buffer)->Tail = (*buffer)->Data;

    (*buffer)->Len = 0;

    RtlZeroMemory(&(*buffer)->WskBufList, sizeof(WSK_BUF_LIST));

    (*buffer)->IoQueue = WDF_NO_HANDLE;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnRxBufferPoolGet(OVPN_RX_BUFFER_POOL handle, OVPN_RX_BUFFER** buffer)
{
    OvpnBufferPoolGet((OVPN_BUFFER_POOL)handle, buffer);
    if (*buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    (*buffer)->Pool = handle;
    (*buffer)->Len = 0;

    return STATUS_SUCCESS;
}

template<class POOL_ENTRY>
static
VOID
OvpnBufferPoolPut(POOL_ENTRY* pool_entry)
{
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)pool_entry->Pool;

    ExInterlockedInsertTailList(&pool->ListHead, &(pool_entry->PoolListEntry), &pool->Lock);
}

_Use_decl_annotations_
VOID
OvpnTxBufferPoolPut(OVPN_TX_BUFFER* buffer)
{
    if (buffer->Mdl)
        IoFreeMdl(buffer->Mdl);

    OvpnBufferPoolPut(buffer);
}

_Use_decl_annotations_
VOID
OvpnRxBufferPoolPut(_In_ OVPN_RX_BUFFER* buffer)
{
    OvpnBufferPoolPut(buffer);
}


template<class POOL_ENTRY>
static
VOID
OvpnBufferPoolDelete(OVPN_BUFFER_POOL handle)
{
    if (handle == NULL)
        return;

    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;

    LIST_ENTRY* list_entry = NULL;
    while ((list_entry = ExInterlockedRemoveHeadList(&pool->ListHead, &pool->Lock)) != NULL) {
        POOL_ENTRY* entry = CONTAINING_RECORD(list_entry, POOL_ENTRY, PoolListEntry);
        ExFreePoolWithTag(entry, 'ovpn');
    }

    ExFreePoolWithTag(pool, 'ovpn');
}

VOID
OvpnRxBufferPoolDelete(OVPN_BUFFER_POOL handle)
{
    OvpnBufferPoolDelete<OVPN_RX_BUFFER>(handle);
}

VOID
OvpnTxBufferPoolDelete(OVPN_BUFFER_POOL handle)
{
    OvpnBufferPoolDelete<OVPN_TX_BUFFER>(handle);
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
    return OvpnBufferPoolCreate((OVPN_BUFFER_POOL*)handle, sizeof(OVPN_RX_BUFFER), "rx", NULL);
}

VOID
OvpnBufferQueueDelete(OVPN_BUFFER_QUEUE handle)
{
    if (handle == NULL)
        return;

    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    ExFreePoolWithTag(queue, 'ovpn');
}
