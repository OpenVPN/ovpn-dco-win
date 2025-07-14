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

#pragma once

#include <ntddk.h>

#include "uapi/ovpn-dco.h"

struct NotifyEvent {
    LIST_ENTRY ListEntry;

    OVPN_NOTIFY_CMD Cmd;
    int PeerId;
    OVPN_DEL_PEER_REASON DelPeerReason;
    struct sockaddr_storage FloatAddress;
};

class NotifyQueue {
private:
    LIST_ENTRY Head;
    KSPIN_LOCK Lock;

public:
    NotifyQueue() = delete;

    VOID Init();

    NTSTATUS AddDelPeerEvent(int peerId, OVPN_DEL_PEER_REASON delPeerReason=OVPN_DEL_PEER_REASON_EXPIRED);
    NTSTATUS AddFloatEvent(int peerId, PSOCKADDR floatAddr);

    NotifyEvent* GetEvent();

    VOID FreeEvent(NotifyEvent* event);

    VOID FlushEvents();

    template<class T>
    static VOID FillFloatPeerEvent(T* evt, INT32 peerId, PSOCKADDR floatAddr)
    {
        RtlZeroMemory(evt, sizeof(T));

        evt->Cmd = OVPN_CMD_FLOAT_PEER;
        evt->PeerId = peerId;

        size_t addr_len;
        switch (floatAddr->sa_family) {
        case AF_INET:
            addr_len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            addr_len = sizeof(struct sockaddr_in6);
            break;
        default:
            // Unsupported or unknown family
            addr_len = sizeof(struct sockaddr_storage); // fallback
            break;
        }
        RtlCopyMemory(&evt->FloatAddress, floatAddr, addr_len);
    }
};
