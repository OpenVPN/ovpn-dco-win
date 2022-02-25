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

#include <ntdef.h>
#include <wdftypes.h>
#include <wdm.h>
#include <wsk.h>

#define OVPN_SOCKET_PACKET_BUFFER_SIZE 2048

DECLARE_HANDLE(OVPN_BUFFER_POOL);
DECLARE_HANDLE(OVPN_TX_BUFFER_POOL);
DECLARE_HANDLE(OVPN_RX_BUFFER_POOL);

DECLARE_HANDLE(OVPN_BUFFER_QUEUE);

struct OVPN_TX_BUFFER
{
    WSK_BUF_LIST WskBufList;

    // points to the beginning of data
    PUCHAR Data;

    // points to the end of data
    PUCHAR Tail;

    // data length
    SIZE_T Len;

    // describes MDL for buffer, used by Winsock Kernel
    PMDL Mdl;

    OVPN_TX_BUFFER_POOL Pool;

    LIST_ENTRY PoolListEntry;

    // used when sending from EvtIoWrite
    WDFQUEUE IoQueue;

#pragma warning(suppress:4200) //nonstandard extension used: zero-sized array in struct/union
    UCHAR Head[];
};

struct OVPN_RX_BUFFER
{
    LIST_ENTRY PoolListEntry;

    LIST_ENTRY QueueListEntry;

    SIZE_T Len;

    OVPN_RX_BUFFER_POOL Pool;

    UCHAR Data[OVPN_SOCKET_PACKET_BUFFER_SIZE];
};

_Must_inspect_result_
UCHAR*
OvpnTxBufferPut(_In_ OVPN_TX_BUFFER* work, SIZE_T len);

UCHAR*
OvpnTxBufferPush(_In_ OVPN_TX_BUFFER* work, SIZE_T len);

_Must_inspect_result_
NTSTATUS
OvpnTxBufferPoolCreate(OVPN_TX_BUFFER_POOL* handle, VOID* ctx);

VOID*
OvpnTxBufferPoolGetContext(OVPN_TX_BUFFER_POOL handle);

_Must_inspect_result_
NTSTATUS
OvpnTxBufferPoolGet(_In_ OVPN_TX_BUFFER_POOL handle, _Outptr_ OVPN_TX_BUFFER** buffer);

VOID
OvpnTxBufferPoolPut(_In_ OVPN_TX_BUFFER* buffer);

_Must_inspect_result_
NTSTATUS
OvpnRxBufferPoolGet(_In_ OVPN_RX_BUFFER_POOL handle, _Outptr_ OVPN_RX_BUFFER** buffer);

VOID
OvpnRxBufferPoolPut(_In_ OVPN_RX_BUFFER* buffer);

_Must_inspect_result_
NTSTATUS
OvpnRxBufferPoolCreate(OVPN_RX_BUFFER_POOL* handle);

NTSTATUS
OvpnBufferQueueCreate(OVPN_BUFFER_QUEUE* handle);

VOID
OvpnBufferQueueEnqueue(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry);

VOID
OvpnBufferQueueEnqueueHead(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry);

LIST_ENTRY*
OvpnBufferQueueDequeue(OVPN_BUFFER_QUEUE handle);

VOID
OvpnRxBufferPoolDelete(OVPN_BUFFER_POOL handle);

VOID
OvpnTxBufferPoolDelete(OVPN_BUFFER_POOL handle);

VOID
OvpnBufferQueueDelete(OVPN_BUFFER_QUEUE handle);