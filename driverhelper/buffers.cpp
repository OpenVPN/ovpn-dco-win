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

#include "..\DMF\Dmf\Modules.Library\DmfModules.Library.h"

#include "buffers.h"
#include "trace.h"

int OVPN_BUFFER_CAPACITY = 2048;

static constexpr int OVPN_BUFFER_HEADROOM = 256;

_Use_decl_annotations_
NTSTATUS
OvpnBufferQueueFetch(OVPN_BUFFER_QUEUE handle, OVPN_RX_BUFFER** buffer)
{
    return DMF_BufferQueue_Fetch((DMFMODULE)handle, (PVOID*)buffer, NULL);
}

_Use_decl_annotations_
VOID
OvpnBufferQueueEnqueue(OVPN_BUFFER_QUEUE handle, OVPN_RX_BUFFER* buffer)
{
    DMF_BufferQueue_Enqueue((DMFMODULE)handle, buffer);
}

_Use_decl_annotations_
NTSTATUS
OvpnBufferQueueDequeue(OVPN_BUFFER_QUEUE handle, OVPN_RX_BUFFER** buffer)
{
    return DMF_BufferQueue_Dequeue((DMFMODULE)handle, (PVOID*)buffer, NULL);
}

_Use_decl_annotations_
VOID
OvpnBufferQueueReuse(OVPN_BUFFER_QUEUE handle, OVPN_RX_BUFFER* buffer)
{
    return DMF_BufferQueue_Reuse((DMFMODULE)handle, buffer);
}

_Use_decl_annotations_
NTSTATUS
OvpnBufferQueueCreate(WDFDEVICE device, OVPN_BUFFER_QUEUE* handle)
{
    WDF_OBJECT_ATTRIBUTES objectAttributes;
    DMF_MODULE_ATTRIBUTES moduleAttributes;
    DMF_CONFIG_BufferQueue bufferQueueConfig;
    DMFMODULE dmfModule;
    NTSTATUS status;

    *handle = nullptr;

    WDF_OBJECT_ATTRIBUTES_INIT(&objectAttributes);
    objectAttributes.ParentObject = device;

    DMF_CONFIG_BufferQueue_AND_ATTRIBUTES_INIT(&bufferQueueConfig, &moduleAttributes);

    bufferQueueConfig.SourceSettings.BufferContextSize = 0;
    bufferQueueConfig.SourceSettings.BufferSize = sizeof(OVPN_TX_BUFFER) + OVPN_BUFFER_CAPACITY;
    bufferQueueConfig.SourceSettings.BufferCount = 0;
    bufferQueueConfig.SourceSettings.CreateWithTimer = FALSE;
    bufferQueueConfig.SourceSettings.EnableLookAside = TRUE;
    bufferQueueConfig.SourceSettings.PoolType = NonPagedPoolNx;

    GOTO_IF_NOT_NT_SUCCESS(done, status, DMF_BufferQueue_Create(device, &moduleAttributes, &objectAttributes, &dmfModule));

    *handle = (OVPN_BUFFER_QUEUE)dmfModule;

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnTxBufferPoolCreate(WDFDEVICE device, OVPN_BUFFER_POOL* handle)
{
    WDF_OBJECT_ATTRIBUTES objectAttributes;
    DMF_MODULE_ATTRIBUTES moduleAttributes;
    DMF_CONFIG_BufferPool bufferPoolConfig;
    DMFMODULE dmfModule;
    NTSTATUS status;

    *handle = nullptr;

    WDF_OBJECT_ATTRIBUTES_INIT(&objectAttributes);
    objectAttributes.ParentObject = device;

    DMF_CONFIG_BufferPool_AND_ATTRIBUTES_INIT(&bufferPoolConfig, &moduleAttributes);

    bufferPoolConfig.BufferPoolMode = BufferPool_ModeType::BufferPool_Mode_Source;
    bufferPoolConfig.Mode.SourceSettings.BufferContextSize = 0;
    bufferPoolConfig.Mode.SourceSettings.BufferSize = sizeof (OVPN_TX_BUFFER) + OVPN_BUFFER_CAPACITY;
    bufferPoolConfig.Mode.SourceSettings.BufferCount = 0;
    bufferPoolConfig.Mode.SourceSettings.CreateWithTimer = FALSE;
    bufferPoolConfig.Mode.SourceSettings.EnableLookAside = TRUE;
    bufferPoolConfig.Mode.SourceSettings.PoolType = NonPagedPoolNx;

    GOTO_IF_NOT_NT_SUCCESS(done, status, DMF_BufferPool_Create(device, &moduleAttributes, &objectAttributes, &dmfModule));

    *handle = (OVPN_BUFFER_POOL)dmfModule;

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnTxBufferPoolGet(OVPN_BUFFER_POOL handle, OVPN_TX_BUFFER** buffer)
{
    NTSTATUS status;

    GOTO_IF_NOT_NT_SUCCESS(done, status, DMF_BufferPool_Get((DMFMODULE)handle, (PVOID*)buffer, NULL));

    (*buffer)->Mdl = IoAllocateMdl(*buffer, sizeof(OVPN_TX_BUFFER) + OVPN_BUFFER_CAPACITY, FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool((*buffer)->Mdl);

    (*buffer)->Pool = handle;

    (*buffer)->Data = (*buffer)->Head + OVPN_BUFFER_HEADROOM;
    (*buffer)->Tail = (*buffer)->Data;

    (*buffer)->Len = 0;

    (*buffer)->IoQueue = WDF_NO_HANDLE;

done:
    return status;
}

_Use_decl_annotations_
VOID
OvpnTxBufferPoolPut(OVPN_TX_BUFFER* buffer)
{
    IoFreeMdl(buffer->Mdl);

    DMF_BufferPool_Put((DMFMODULE)buffer->Pool, buffer);
}

_Use_decl_annotations_
WDFDEVICE
OvpnTxBufferPoolGetParentDevice(_In_ OVPN_BUFFER_POOL handle)
{
    return DMF_ParentDeviceGet((DMFMODULE)handle);
}

_Use_decl_annotations_
PUCHAR
OvpnTxBufferPut(OVPN_TX_BUFFER* buffer, SIZE_T len)
{
    PUCHAR tmp = buffer->Tail;
    buffer->Tail += len;
    buffer->Len += len;

    return tmp;
}

_Use_decl_annotations_
PUCHAR
OvpnTxBufferPush(OVPN_TX_BUFFER* buffer, SIZE_T len)
{
    buffer->Data -= len;
    buffer->Len += len;

    return buffer->Data;
}
