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

#include "adapter.h"
#include "txqueue.h"
#include "rxqueue.h"
#include "trace.h"
#include "driver.h"

// maximum link speed for send and recv in bps
#define OVPN_MEDIA_MAX_SPEED 1'000'000'000

static void
OvpnAdapterSetDatapathCapabilities(_In_ POVPN_ADAPTER adapter)
{
    NET_ADAPTER_TX_CAPABILITIES txCapabilities;
    NET_ADAPTER_TX_CAPABILITIES_INIT(&txCapabilities, 1);

    NET_ADAPTER_RX_CAPABILITIES rxCapabilities;
    NET_ADAPTER_RX_CAPABILITIES_INIT_SYSTEM_MANAGED(&rxCapabilities, 65536, 1);

    NetAdapterSetDataPathCapabilities(adapter->NetAdapter, &txCapabilities, &rxCapabilities);
}

static
void
OvpnAdapterSetLinkLayerCapabilities(_In_ POVPN_ADAPTER adapter)
{
    ULONG64 maxXmitLinkSpeed = OVPN_MEDIA_MAX_SPEED;
    ULONG64 maxRcvLinkSpeed = OVPN_MEDIA_MAX_SPEED;

    NET_ADAPTER_LINK_LAYER_CAPABILITIES linkLayerCapabilities;
    NET_ADAPTER_LINK_LAYER_CAPABILITIES_INIT(&linkLayerCapabilities,
                                             maxXmitLinkSpeed,
                                             maxRcvLinkSpeed);

    NetAdapterSetLinkLayerCapabilities(adapter->NetAdapter, &linkLayerCapabilities);
    NetAdapterSetLinkLayerMtuSize(adapter->NetAdapter, 0xFFFF);
}

static
void
OvpnAdapterSetLinkState(_In_ POVPN_ADAPTER adapter)
{
    NET_ADAPTER_LINK_STATE linkState;
    NET_ADAPTER_LINK_STATE_INIT(&linkState,
                                OVPN_MEDIA_MAX_SPEED,
                                NET_IF_MEDIA_CONNECT_STATE::MediaConnectStateConnected,
                                NET_IF_MEDIA_DUPLEX_STATE::MediaDuplexStateFull,
                                NET_ADAPTER_PAUSE_FUNCTION_TYPE::NetAdapterPauseFunctionTypeUnsupported,
                                NET_ADAPTER_AUTO_NEGOTIATION_FLAGS::NetAdapterAutoNegotiationFlagNone);
    NetAdapterSetLinkState(adapter->NetAdapter, &linkState);
}


_Use_decl_annotations_
VOID
OvpnAdapterDestroy(NETADAPTER netAdapter)
{
    if (netAdapter == WDF_NO_HANDLE)
        return;

    POVPN_ADAPTER adapter = OvpnGetAdapterContext(netAdapter);
    POVPN_DEVICE device = OvpnGetDeviceContext(adapter->WdfDevice);

    KIRQL irql = ExAcquireSpinLockExclusive(&device->SpinLock);
    device->Adapter = WDF_NO_HANDLE;
    ExReleaseSpinLockExclusive(&device->SpinLock, irql);

    NetAdapterStop(netAdapter);
    WdfObjectDelete(netAdapter);
}

EVT_NET_ADAPTER_CREATE_TXQUEUE OvpnEvtAdapterCreateTxQueue;

_Use_decl_annotations_
NTSTATUS
OvpnEvtAdapterCreateTxQueue(NETADAPTER netAdapter, _Inout_ NETTXQUEUE_INIT* txQueueInit)
{
    WDF_OBJECT_ATTRIBUTES txAttributes;
    NET_PACKET_QUEUE_CONFIG txConfig;

    NET_PACKET_QUEUE_CONFIG_INIT(&txConfig, OvpnEvtTxQueueAdvance, OvpnEvtTxQueueSetNotificationEnabled, OvpnEvtTxQueueCancel);

    NETPACKETQUEUE txQueue;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&txAttributes, OVPN_TXQUEUE);
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, NetTxQueueCreate(txQueueInit, &txAttributes, &txConfig, &txQueue));

    OvpnTxQueueInitialize(txQueue, OvpnGetAdapterContext(netAdapter));

 done:
    return status;
}

EVT_NET_ADAPTER_CREATE_RXQUEUE OvpnEvtAdapterCreateRxQueue;

_Use_decl_annotations_
NTSTATUS
OvpnEvtAdapterCreateRxQueue(NETADAPTER netAdapter, NETRXQUEUE_INIT* rxQueueInit)
{
    WDF_OBJECT_ATTRIBUTES rxAttributes;
    NET_PACKET_QUEUE_CONFIG rxConfig;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&rxAttributes, OVPN_RXQUEUE);
    NET_PACKET_QUEUE_CONFIG_INIT(&rxConfig, OvpnEvtRxQueueAdvance, OvpnEvtRxQueueSetNotificationEnabled, OvpnEvtRxQueueCancel);

    NETPACKETQUEUE netPacketQueue;
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, NetRxQueueCreate(rxQueueInit, &rxAttributes, &rxConfig, &netPacketQueue));

    POVPN_ADAPTER adapterContext = OvpnGetAdapterContext(netAdapter);
    OvpnRxQueueInitialize(netPacketQueue, adapterContext);
    adapterContext->RxQueue = netPacketQueue;

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnAdapterCreate(OVPN_DEVICE * device) {
    NTSTATUS status = STATUS_SUCCESS;

    NETADAPTER_INIT* adapterInit = NetAdapterInitAllocate(device->WdfDevice);
    if (adapterInit == NULL) {
        return status;
    }

    NET_ADAPTER_DATAPATH_CALLBACKS datapathCallbacks;
    NET_ADAPTER_DATAPATH_CALLBACKS_INIT(&datapathCallbacks, OvpnEvtAdapterCreateTxQueue, OvpnEvtAdapterCreateRxQueue);
    NetAdapterInitSetDatapathCallbacks(adapterInit, &datapathCallbacks);

    NetAdapterInitSetDatapathCallbacks(adapterInit, &datapathCallbacks);

    WDF_OBJECT_ATTRIBUTES adapterAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&adapterAttributes, OVPN_ADAPTER);

    NETADAPTER netAdapter;
    GOTO_IF_NOT_NT_SUCCESS(createfailure, status, NetAdapterCreate(adapterInit, &adapterAttributes, &netAdapter));

    POVPN_ADAPTER adapter = OvpnGetAdapterContext(netAdapter);
    adapter->NetAdapter = netAdapter;
    adapter->WdfDevice = device->WdfDevice;

    NetAdapterInitFree(adapterInit);
    adapterInit = NULL;

    OvpnAdapterSetDatapathCapabilities(adapter);
    OvpnAdapterSetLinkLayerCapabilities(adapter);

    OvpnAdapterSetLinkState(adapter);

    status = NetAdapterStart(adapter->NetAdapter);

    KIRQL irql = ExAcquireSpinLockExclusive(&device->SpinLock);
    device->Adapter = netAdapter;
    ExReleaseSpinLockExclusive(&device->SpinLock, irql);

    goto done;

createfailure:
    NetAdapterInitFree(adapterInit);
    adapterInit = NULL;

done:
    return status;
}

NTSTATUS OvpnAdapterNotifyRx(NETADAPTER netAdapter)
{
    if (netAdapter == WDF_NO_HANDLE) {
        LOG_ERROR("Adapter not initialized");
        return STATUS_DEVICE_NOT_READY;
    }

    NETPACKETQUEUE rxQueue = OvpnGetAdapterContext(netAdapter)->RxQueue;
    POVPN_RXQUEUE queueContext = OvpnGetRxQueueContext(rxQueue);

    if (InterlockedExchange(&queueContext->NotificationEnabled, FALSE) == TRUE)
        NetRxQueueNotifyMoreReceivedPacketsAvailable(rxQueue);

    return STATUS_SUCCESS;
}
