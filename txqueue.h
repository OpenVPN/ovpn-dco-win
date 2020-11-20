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

typedef struct _OVPN_TXQUEUE
{
    POVPN_ADAPTER Adapter;

    NET_RING_COLLECTION const * Rings;

    NET_EXTENSION VirtualAddressExtension;
} OVPN_TXQUEUE, * POVPN_TXQUEUE;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_TXQUEUE, OvpnGetTxQueueContext);

EVT_PACKET_QUEUE_SET_NOTIFICATION_ENABLED OvpnEvtTxQueueSetNotificationEnabled;
EVT_PACKET_QUEUE_ADVANCE OvpnEvtTxQueueAdvance;
EVT_PACKET_QUEUE_CANCEL OvpnEvtTxQueueCancel;

VOID
OvpnTxQueueInitialize(NETPACKETQUEUE txQueue, _In_ POVPN_ADAPTER adapter);
