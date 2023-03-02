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
#include <netadaptercx.h>

#define OVPN_DCO_MTU_MAX 1500

// Context for NETADAPTER
struct OVPN_ADAPTER
{
    // WDF handles associated with this context
    NETADAPTER NetAdapter;
    WDFDEVICE WdfDevice;

    // Handle to Rx Queue
    NETPACKETQUEUE RxQueue;
};

typedef OVPN_ADAPTER * POVPN_ADAPTER;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_ADAPTER, OvpnGetAdapterContext);

struct OVPN_DEVICE;

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
OvpnAdapterCreate(OVPN_DEVICE* device);

// notify NetAdapter (if it is ready) that more packets are available
VOID
OvpnAdapterNotifyRx(NETADAPTER netAdapter);

VOID
OvpnAdapterSetLinkState(_In_ POVPN_ADAPTER adapter, NET_IF_MEDIA_CONNECT_STATE state);

#define OVPN_PAYLOAD_BACKFILL 26 // 2 + 4 + 4 + 16 -> tcp packet size + data_v2 + pktid + auth-tag;