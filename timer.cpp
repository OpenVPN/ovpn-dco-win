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

// without this include, RTL_GENERIC_TABLE in Device.h is undefined
#include <ntddk.h>

#include "bufferpool.h"
#include "driver.h"
#include "trace.h"
#include "timer.h"
#include "socket.h"
#include "peer.h"

static const UCHAR OvpnKeepaliveMessage[] = {
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

// Context added to a timer's attributes
typedef struct _OVPN_PEER_TIMER_CONTEXT {
    OvpnPeerContext* Peer;
} OVPN_PEER_TIMER_CONTEXT, * POVPN_PEER_TIMER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_PEER_TIMER_CONTEXT, OvpnGetPeerTimerContext);

_Use_decl_annotations_
BOOLEAN OvpnTimerIsKeepaliveMessage(const PUCHAR buf, SIZE_T len)
{
    return RtlCompareMemory(buf, OvpnKeepaliveMessage, len) == sizeof(OvpnKeepaliveMessage);
}

_Function_class_(EVT_WDF_TIMER)
static VOID OvpnTimerXmit(WDFTIMER timer)
{
    LOG_ENTER();

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfTimerGetParentObject(timer));
    POVPN_PEER_TIMER_CONTEXT timerCtx = OvpnGetPeerTimerContext(timer);
    OVPN_TX_BUFFER* buffer;
    NTSTATUS status;

    LOG_IF_NOT_NT_SUCCESS(status = OvpnTxBufferPoolGet(device->TxBufferPool, &buffer));

    if (!NT_SUCCESS(status)) {
        LOG_EXIT();
        return;
    }

    // copy keepalive magic message to the buffer
    RtlCopyMemory(OvpnTxBufferPut(buffer, sizeof(OvpnKeepaliveMessage)), OvpnKeepaliveMessage, sizeof(OvpnKeepaliveMessage));

    OvpnPeerContext* peer = timerCtx->Peer;
    KIRQL kiqrl = ExAcquireSpinLockShared(&device->SpinLock);
    if (peer->CryptoContext.Encrypt) {
        // make space to crypto overhead
        OvpnTxBufferPush(buffer, device->CryptoOverhead);

        // in-place encrypt, always with primary key
        status = peer->CryptoContext.Encrypt(&peer->CryptoContext.Primary, buffer->Data, buffer->Len);
    }
    else {
        status = STATUS_INVALID_DEVICE_STATE;
        // LOG_WARN("CryptoContext not initialized");
    }

    if (NT_SUCCESS(status)) {
        // start async send, completion handler will return ciphertext buffer to the pool
        LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketSend(&device->Socket, buffer));
        if (NT_SUCCESS(status)) {
            LOG_INFO("Ping sent");
        }
    }
    else {
        OvpnTxBufferPoolPut(buffer);
    }
    ExReleaseSpinLockShared(&device->SpinLock, kiqrl);

    LOG_EXIT();
}

_Function_class_(EVT_WDF_TIMER)
static VOID OvpnTimerRecv(WDFTIMER timer)
{
    LOG_ENTER();

    LOG_WARN("Keepalive timeout");

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfTimerGetParentObject(timer));

    WDFREQUEST request;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request);
    if (!NT_SUCCESS(status)) {
        LOG_WARN("No pending request for keepalive timeout notification");
    }
    else {
        ULONG_PTR bytesSent = 0;
        WdfRequestCompleteWithInformation(request, STATUS_CONNECTION_DISCONNECTED, bytesSent);
    }

    LOG_EXIT();
}

_Use_decl_annotations_
VOID OvpnTimerDestroy(WDFTIMER* timer)
{
    if (*timer != WDF_NO_HANDLE) {
        WdfTimerStop(*timer, FALSE);
        WdfObjectDelete(*timer);

        *timer = WDF_NO_HANDLE;
    }
}

static NTSTATUS OvpnTimerCreate(WDFOBJECT parent, OvpnPeerContext* peer, ULONG period, PFN_WDF_TIMER func, _Inout_ WDFTIMER* timer)
{
    LOG_ENTER();

    if (*timer != WDF_NO_HANDLE) {
        WdfTimerStop(*timer, FALSE);
        WdfObjectDelete(*timer);

        *timer = WDF_NO_HANDLE;
    }

    WDF_TIMER_CONFIG timerConfig;
    WDF_TIMER_CONFIG_INIT(&timerConfig, func);
    timerConfig.Period = period * 1000;

    WDF_OBJECT_ATTRIBUTES timerAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&timerAttributes);
    WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&timerAttributes, OVPN_PEER_TIMER_CONTEXT);
    timerAttributes.ParentObject = parent;

    *timer = WDF_NO_HANDLE;
    NTSTATUS status;
    LOG_IF_NOT_NT_SUCCESS(status = WdfTimerCreate(&timerConfig, &timerAttributes, timer));
    if (NT_SUCCESS(status)) {
        POVPN_PEER_TIMER_CONTEXT pTimerContext = OvpnGetPeerTimerContext(*timer);
        pTimerContext->Peer = peer;
    }

    LOG_EXIT();
    return status;
}

_Use_decl_annotations_
NTSTATUS OvpnTimerXmitCreate(WDFOBJECT parent, OvpnPeerContext* peer, ULONG period, WDFTIMER* timer)
{
    NTSTATUS status;
    LOG_INFO("Create xmit timer", TraceLoggingValue(period, "period"));
    LOG_IF_NOT_NT_SUCCESS(status = OvpnTimerCreate(parent, peer, period, OvpnTimerXmit, timer));

    return status;
}

_Use_decl_annotations_
NTSTATUS OvpnTimerRecvCreate(WDFOBJECT parent, OvpnPeerContext* peer, WDFTIMER* timer)
{
    NTSTATUS status;
    LOG_INFO("Create recv timer");
    LOG_IF_NOT_NT_SUCCESS(status = OvpnTimerCreate(parent, peer, 0, OvpnTimerRecv, timer));

    return status;
}

VOID OvpnTimerReset(WDFTIMER timer, ULONG dueTime)
{
    if (timer != WDF_NO_HANDLE) {
        // if timer has already been created this will reset "due time" value to the new one
        WdfTimerStart(timer, WDF_REL_TIMEOUT_IN_SEC(dueTime));
    }
}
