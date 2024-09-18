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

    LARGE_INTEGER lastXmit;
    LARGE_INTEGER lastRecv;

    // 0 means "not set"
    LONG recvTimeout;
    LONG xmitInterval;
} OVPN_PEER_TIMER_CONTEXT, * POVPN_PEER_TIMER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_PEER_TIMER_CONTEXT, OvpnGetPeerTimerContext);

_Use_decl_annotations_
BOOLEAN OvpnTimerIsKeepaliveMessage(const PUCHAR buf, SIZE_T len)
{
    return RtlCompareMemory(buf, OvpnKeepaliveMessage, len) == sizeof(OvpnKeepaliveMessage);
}

static VOID OvpnTimerXmit(WDFTIMER timer)
{
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
    OvpnCryptoContext* cryptoContext = &peer->CryptoContext;
    if (cryptoContext->Encrypt) {
        // make space to crypto overhead
        BOOLEAN pktId64bit = cryptoContext->CryptoOptions & CRYPTO_OPTIONS_64BIT_PKTID;
        BOOLEAN aeadTagEnd = cryptoContext->CryptoOptions & CRYPTO_OPTIONS_AEAD_TAG_END;
        
        OvpnTxBufferPush(buffer, OVPN_DATA_V2_LEN + (pktId64bit ? 8 : 4) + (aeadTagEnd ? 0 : AEAD_AUTH_TAG_LEN));

        // in-place encrypt, always with primary key
        status = cryptoContext->Encrypt(&cryptoContext->Primary, buffer->Data, buffer->Len, cryptoContext->CryptoOptions);
    }
    else {
        status = STATUS_INVALID_DEVICE_STATE;
        // LOG_WARN("CryptoContext not initialized");
    }

    if (NT_SUCCESS(status)) {
        // start async send, completion handler will return ciphertext buffer to the pool
        LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketSend(&device->Socket, buffer, NULL));
        if (NT_SUCCESS(status)) {
            LOG_INFO("Ping sent");
        }
    }
    else {
        OvpnTxBufferPoolPut(buffer);
    }
    ExReleaseSpinLockShared(&device->SpinLock, kiqrl);
}

static BOOLEAN OvpnTimerRecv(WDFTIMER timer)
{
    POVPN_DEVICE device = OvpnGetDeviceContext(WdfTimerGetParentObject(timer));

    WDFREQUEST request;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request);
    if (!NT_SUCCESS(status)) {
        LOG_WARN("No pending request for keepalive timeout notification");
        return FALSE;
    }
    else {
        LOG_INFO("Notify userspace about keepalive timeout");
        ULONG_PTR bytesSent = 0;
        WdfRequestCompleteWithInformation(request, STATUS_CONNECTION_DISCONNECTED, bytesSent);
        return TRUE;
    }
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

_Function_class_(EVT_WDF_TIMER)
static VOID OvpnTimerTick(WDFTIMER timer)
{
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    POVPN_PEER_TIMER_CONTEXT timerCtx = OvpnGetPeerTimerContext(timer);
    if ((timerCtx->xmitInterval > 0) && (((now.QuadPart - timerCtx->lastXmit.QuadPart) / WDF_TIMEOUT_TO_SEC) > timerCtx->xmitInterval))
    {
        OvpnTimerXmit(timer);
        timerCtx->lastXmit = now;
    }

    if ((timerCtx->recvTimeout > 0) && (((now.QuadPart - timerCtx->lastRecv.QuadPart) / WDF_TIMEOUT_TO_SEC) > timerCtx->recvTimeout))
    {
        // have we have completed pending read request?
        if (OvpnTimerRecv(timer))
        {
            timerCtx->recvTimeout = 0; // one-off timer
        }
    }
}

_Use_decl_annotations_
NTSTATUS OvpnTimerCreate(WDFOBJECT parent, OvpnPeerContext* peer, _Inout_ WDFTIMER* timer)
{
    LOG_ENTER();

    if (*timer != WDF_NO_HANDLE) {
        WdfTimerStop(*timer, FALSE);
        WdfObjectDelete(*timer);

        *timer = WDF_NO_HANDLE;
    }

    WDF_TIMER_CONFIG timerConfig;
    WDF_TIMER_CONFIG_INIT(&timerConfig, OvpnTimerTick);
    timerConfig.TolerableDelay = TolerableDelayUnlimited;
    timerConfig.Period = 1000;

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
        WdfTimerStart(*timer, WDF_REL_TIMEOUT_IN_SEC(1));
    }

    LOG_EXIT();
    return status;
}

#define CHECK_TIMER_HANDLE(timer) \
    do { \
        if ((timer) == WDF_NO_HANDLE) { \
            LOG_ERROR("Timer handle is not initialized"); \
            return; \
        } \
    } while (0)

VOID OvpnTimerSetXmitInterval(WDFTIMER timer, LONG xmitInterval)
{
    CHECK_TIMER_HANDLE(timer);

    POVPN_PEER_TIMER_CONTEXT timerCtx = OvpnGetPeerTimerContext(timer);
    timerCtx->xmitInterval = xmitInterval;
    KeQuerySystemTime(&timerCtx->lastXmit);
}

VOID OvpnTimerSetRecvTimeout(WDFTIMER timer, LONG recvTimeout)
{
    CHECK_TIMER_HANDLE(timer);

    POVPN_PEER_TIMER_CONTEXT timerCtx = OvpnGetPeerTimerContext(timer);
    timerCtx->recvTimeout = recvTimeout;
    KeQuerySystemTime(&timerCtx->lastRecv);
}

VOID OvpnTimerResetXmit(WDFTIMER timer)
{
    CHECK_TIMER_HANDLE(timer);

    POVPN_PEER_TIMER_CONTEXT timerCtx = OvpnGetPeerTimerContext(timer);
    KeQuerySystemTime(&timerCtx->lastXmit);
}

VOID OvpnTimerResetRecv(WDFTIMER timer)
{
    CHECK_TIMER_HANDLE(timer);

    POVPN_PEER_TIMER_CONTEXT timerCtx = OvpnGetPeerTimerContext(timer);
    KeQuerySystemTime(&timerCtx->lastRecv);
}
