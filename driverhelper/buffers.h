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

#include <ntddk.h>
#include <wdf.h>

DECLARE_HANDLE(OVPN_BUFFER_QUEUE);

extern int OVPN_BUFFER_CAPACITY;

struct OVPN_RX_BUFFER
{
    SIZE_T Len;

#pragma warning(suppress:4200) //nonstandard extension used: zero-sized array in struct/union
    UCHAR Head[];
};

VOID
OvpnBufferQueueFlushPending(_In_ OVPN_BUFFER_QUEUE handle);

_Must_inspect_result_
NTSTATUS
OvpnBufferQueueCreate(_In_ WDFDEVICE Device, _Outptr_ OVPN_BUFFER_QUEUE* Handle);

_Must_inspect_result_
NTSTATUS
OvpnBufferQueueFetch(_In_ OVPN_BUFFER_QUEUE Handle, _Outptr_ OVPN_RX_BUFFER** Buffer);

VOID
OvpnBufferQueueEnqueue(_In_ OVPN_BUFFER_QUEUE Handle, _In_ OVPN_RX_BUFFER* Buffer);

_Must_inspect_result_
NTSTATUS
OvpnBufferQueueDequeue(_In_ OVPN_BUFFER_QUEUE Handle, _Outptr_ OVPN_RX_BUFFER** Buffer);

VOID
OvpnBufferQueueReuse(_In_ OVPN_BUFFER_QUEUE Handle, _In_ OVPN_RX_BUFFER* Buffer);

DECLARE_HANDLE(OVPN_BUFFER_POOL);

struct OVPN_TX_BUFFER
{
    // points to the beginning of data
    PUCHAR Data;

    // points to the end of data
    PUCHAR Tail;

    // data length
    SIZE_T Len;

    // describes MDL for buffer, used by Winsock Kernel
    PMDL Mdl;

    OVPN_BUFFER_POOL Pool;

    // used when sending from EvtIoWrite
    WDFQUEUE IoQueue;

#pragma warning(suppress:4200) //nonstandard extension used: zero-sized array in struct/union
    UCHAR Head[];
};

_Must_inspect_result_
PUCHAR OvpnTxBufferPut(_In_ OVPN_TX_BUFFER* buffer, SIZE_T len);

PUCHAR OvpnTxBufferPush(_In_ OVPN_TX_BUFFER* buffer, SIZE_T len);

_Must_inspect_result_
NTSTATUS
OvpnTxBufferPoolCreate(_In_ WDFDEVICE device, _Outptr_ OVPN_BUFFER_POOL* handle);

_Must_inspect_result_
NTSTATUS
OvpnTxBufferPoolGet(_In_ OVPN_BUFFER_POOL handle, _Outptr_ OVPN_TX_BUFFER** buffer);

VOID
OvpnTxBufferPoolPut(_In_ OVPN_TX_BUFFER* buffer);

WDFDEVICE
OvpnTxBufferPoolGetParentDevice(_In_ OVPN_BUFFER_POOL handle);
