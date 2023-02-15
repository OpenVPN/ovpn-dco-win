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

typedef struct _OVPN_RXQUEUE
{
    POVPN_ADAPTER Adapter;

    NET_RING_COLLECTION const * Rings;

    NET_EXTENSION VirtualAddressExtension;
    NET_EXTENSION ChecksumExtension;

    LONG NotificationEnabled = 0;
} OVPN_RXQUEUE, * POVPN_RXQUEUE;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_RXQUEUE, OvpnGetRxQueueContext);

EVT_PACKET_QUEUE_SET_NOTIFICATION_ENABLED OvpnEvtRxQueueSetNotificationEnabled;
EVT_PACKET_QUEUE_ADVANCE OvpnEvtRxQueueAdvance;
EVT_PACKET_QUEUE_CANCEL OvpnEvtRxQueueCancel;

EVT_PACKET_QUEUE_START OvpnEvtRxQueueStart;
EVT_PACKET_QUEUE_STOP OvpnEvtRxQueueStop;

EVT_WDF_OBJECT_CONTEXT_DESTROY OvpnEvtRxQueueDestroy;

VOID
OvpnRxQueueInitialize(NETPACKETQUEUE rxQueue, _In_ POVPN_ADAPTER adapter);
