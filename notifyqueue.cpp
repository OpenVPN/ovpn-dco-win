/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2024- OpenVPN Inc <sales@openvpn.net>
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

#include "notifyqueue.h"

#include "trace.h"

VOID
NotifyQueue::Init()
{
    LOG_ENTER();

    InitializeListHead(&Head);
    KeInitializeSpinLock(&Lock);

    LOG_EXIT();
}

NTSTATUS
NotifyQueue::AddEvent(OVPN_NOTIFY_CMD cmd, int peerId, OVPN_DEL_PEER_REASON delPeerReason)
{
    NotifyEvent* event = (NotifyEvent*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NotifyEvent), 'ovpn');
    if (!event) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    RtlZeroMemory(event, sizeof(NotifyEvent));

    event->Cmd = cmd;
    event->PeerId = peerId;
    event->DelPeerReason = delPeerReason;

    ExInterlockedInsertTailList(&Head, &event->ListEntry, &Lock);

    return STATUS_SUCCESS;
}

NotifyEvent*
NotifyQueue::GetEvent()
{
    PLIST_ENTRY entry = ExInterlockedRemoveHeadList(&Head, &Lock);
    if (entry == nullptr) {
        return nullptr;
    }

    return CONTAINING_RECORD(entry, NotifyEvent, ListEntry);
}

VOID
NotifyQueue::FreeEvent(NotifyEvent* event)
{
    if (event != nullptr) {
        ExFreePoolWithTag(event, 'ovpn');
    }
}

VOID
NotifyQueue::FlushEvents()
{
    LOG_ENTER();

    NotifyEvent* event = nullptr;
    while ((event = GetEvent()) != nullptr) {
        FreeEvent(event);
    }

    LOG_EXIT();
}
