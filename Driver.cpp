/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2023 Rubicon Communications LLC (Netgate)
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

#include <intrin.h>
#include <ntddk.h>
#include <wsk.h>
#include <wdf.h>
#include <wdfrequest.h>

#include "bufferpool.h"
#include "control.h"
#include "driver.h"
#include "trace.h"
#include "peer.h"
#include "uapi\ovpn-dco.h"
#include "socket.h"

TRACELOGGING_DEFINE_PROVIDER(g_hOvpnEtwProvider,
  "OpenVPN.OvpnDCO",
  (0x4970f9cf, 0x2c0c, 0x4f11, 0xb1, 0xcc, 0xe3, 0xa1, 0xe9, 0x95, 0x88, 0x33));

// WSK Client Dispatch table that denotes the WSK version
// that the WSK application wants to use and optionally a pointer
// to the WskClientEvent callback function
const WSK_CLIENT_DISPATCH WskAppDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };

EVT_WDF_DRIVER_UNLOAD OvpnEvtDriverUnload;

_Use_decl_annotations_
VOID
OvpnEvtDriverUnload(_In_ WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);

    LOG_ENTER();
    LOG_EXIT();

    TraceLoggingUnregister(g_hOvpnEtwProvider);

    // tail call optimization incorrectly eliminates TraceLoggingUnregister() call
    // add __nop() to prevent TCO
    __nop();
}

EVT_WDF_OBJECT_CONTEXT_CLEANUP OvpnEvtDriverCleanup;

_Use_decl_annotations_
VOID OvpnEvtDriverCleanup(_In_ WDFOBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);

    LOG_ENTER();
    LOG_EXIT();
}

EXTERN_C DRIVER_INITIALIZE DriverEntry;

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

_Use_decl_annotations_
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath)
{
    WSK_CLIENT_NPI wskClientNpi = {};

    NTSTATUS status;
    BOOLEAN traceLoggingRegistered = FALSE;
    GOTO_IF_NOT_NT_SUCCESS(done, status, TraceLoggingRegister(g_hOvpnEtwProvider));
    traceLoggingRegistered = TRUE;

    LOG_INFO("Driver Version", TraceLoggingValue(OVPN_DCO_VERSION_MAJOR, "Major"),
        TraceLoggingValue(OVPN_DCO_VERSION_MINOR, "Minor"),
        TraceLoggingValue(OVPN_DCO_VERSION_PATCH, "Patch"));

    WDF_OBJECT_ATTRIBUTES driverAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttrs);
    WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&driverAttrs, OVPN_DRIVER);
    driverAttrs.EvtCleanupCallback = OvpnEvtDriverCleanup;

    WDF_DRIVER_CONFIG driverConfig;
    WDF_DRIVER_CONFIG_INIT(&driverConfig, OvpnEvtDeviceAdd);
    driverConfig.EvtDriverUnload = OvpnEvtDriverUnload;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDriverCreate(driverObject, registryPath, &driverAttrs, &driverConfig, WDF_NO_HANDLE));

    // Register the WSK application
    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &WskAppDispatch;

    POVPN_DRIVER driverCtx = OvpnGetDriverContext(WdfGetDriver());
    GOTO_IF_NOT_NT_SUCCESS(done, status, WskRegister(&wskClientNpi, &driverCtx->WskRegistration));

done:
    if (traceLoggingRegistered) {
        if (!NT_SUCCESS(status)) {
            TraceLoggingUnregister(g_hOvpnEtwProvider);
        }
    }

    LOG_EXIT();

    return status;
}

EVT_WDF_IO_QUEUE_IO_READ OvpnEvtIoRead;

_Use_decl_annotations_
VOID
OvpnEvtIoRead(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
    UNREFERENCED_PARAMETER(length);

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    // do we have pending control packets?
    LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->ControlRxBufferQueue);
    if (entry == NULL) {
        // no pending control packets, move request to manual queue
        LOG_IF_NOT_NT_SUCCESS(WdfRequestForwardToIoQueue(request, device->PendingReadsQueue));
        return;
    }

    OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(entry, OVPN_RX_BUFFER, QueueListEntry);

    NTSTATUS status;

    // retrieve IO request buffer
    PVOID inputBuffer;
    size_t inputBufferLength;

    ULONG_PTR bytesSent = buffer->Len;

    LOG_IF_NOT_NT_SUCCESS(status = WdfRequestRetrieveOutputBuffer(request, buffer->Len, &inputBuffer, &inputBufferLength));
    if (NT_SUCCESS(status)) {
        // copy packet into IO request buffer
        RtlCopyMemory(inputBuffer, buffer->Data, buffer->Len);
        InterlockedIncrementNoFence(&device->Stats.ReceivedControlPackets);
    }
    else {
        if (status == STATUS_BUFFER_TOO_SMALL) {
            LOG_ERROR("Buffer too small, packet size <pktsize>, buffer size <bufsize>",
                TraceLoggingValue(buffer->Len, "pktsize"), TraceLoggingValue(inputBufferLength, "bufsize"));
        }

        bytesSent = 0;
    }

    // complete IO request
    WdfRequestCompleteWithInformation(request, status, bytesSent);

    // return buffer back to pool
    OvpnRxBufferPoolPut(buffer);
}

EVT_WDF_IO_QUEUE_IO_READ OvpnEvtIoWrite;

_Use_decl_annotations_
VOID
OvpnEvtIoWrite(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
    UNREFERENCED_PARAMETER(length);

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    // acquire spinlock, since we access device->TransportSocket
    KIRQL kiqrl = ExAcquireSpinLockShared(&device->SpinLock);

    OVPN_TX_BUFFER* txBuf = NULL;

    if (device->Socket.Socket == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        LOG_ERROR("TransportSocket is not initialized");
        goto error;
    }

    // get request buffer
    PVOID buf;
    size_t bufLen;
    GOTO_IF_NOT_NT_SUCCESS(error, status, WdfRequestRetrieveInputBuffer(request, 0, &buf, &bufLen));

    PSOCKADDR sa = NULL;

    if (device->Mode == OVPN_MODE_MP) {
        // buffer is prepended with SOCKADDR

        sa = (PSOCKADDR)buf;
        switch (sa->sa_family) {
        case AF_INET:
            if (bufLen <= sizeof(SOCKADDR_IN)) {
                status = STATUS_INVALID_MESSAGE;
                LOG_ERROR("Message too short", TraceLoggingValue(bufLen, "msgLen"), TraceLoggingValue(sizeof(SOCKADDR_IN), "minLen"));
                goto error;
            }

            buf = (char*)buf + sizeof(SOCKADDR_IN);
            bufLen -= sizeof(SOCKADDR_IN);
            break;

        case AF_INET6:
            if (bufLen <= sizeof(SOCKADDR_IN6)) {
                status = STATUS_INVALID_MESSAGE;
                LOG_ERROR("Message too short", TraceLoggingValue(bufLen, "msgLen"), TraceLoggingValue(sizeof(SOCKADDR_IN6), "minLen"));
                goto error;
            }

            buf = (char*)buf + sizeof(SOCKADDR_IN6);
            bufLen -= sizeof(SOCKADDR_IN6);
            break;

        default:
            LOG_ERROR("Invalid address family", TraceLoggingValue(sa->sa_family, "AF"));
            status = STATUS_INVALID_ADDRESS;
            goto error;
        }
    }

    // fetch tx buffer
    GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnTxBufferPoolGet(device->TxBufferPool, &txBuf));

    // copy data from request to tx buffer
    PUCHAR data = OvpnBufferPut(txBuf, bufLen);
    RtlCopyMemory(data, buf, bufLen);

    txBuf->IoQueue = device->PendingWritesQueue;

    // move request to manual queue
    GOTO_IF_NOT_NT_SUCCESS(error, status, WdfRequestForwardToIoQueue(request, device->PendingWritesQueue));

    // send
    LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketSend(&device->Socket, txBuf, sa));

    goto done_not_complete;

error:
    if (txBuf != NULL) {
        OvpnTxBufferPoolPut(txBuf);
    }

    ULONG_PTR bytesCopied = 0;
    WdfRequestCompleteWithInformation(request, status, bytesCopied);

done_not_complete:
    ExReleaseSpinLockShared(&device->SpinLock, kiqrl);
}

NTSTATUS
OvpnSetMode(POVPN_DEVICE device, WDFREQUEST request)
{
    POVPN_SET_MODE mode;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_SET_MODE), (PVOID*)&mode, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (device->Mode != OVPN_MODE_P2P) {
        LOG_ERROR("mode already set");
        return STATUS_ALREADY_INITIALIZED;
    }

    status = STATUS_SUCCESS;

    LOG_INFO("Set mode", TraceLoggingValue(static_cast<int>(mode->Mode), "mode"));

    switch (mode->Mode) {
    case OVPN_MODE_P2P:
    case OVPN_MODE_MP:
        device->Mode = mode->Mode;
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

static BOOLEAN
OvpnDeviceCheckMode(OVPN_MODE mode, ULONG code)
{
    if (mode == OVPN_MODE_MP) {
        switch (code) {
        // all those IOCTLs are only for P2P mode
        case OVPN_IOCTL_NEW_PEER:
        case OVPN_IOCTL_DEL_PEER:
        case OVPN_IOCTL_SWAP_KEYS:
        case OVPN_IOCTL_SET_PEER:
        case OVPN_IOCTL_START_VPN:
            return FALSE;
        }
    }
    else if (mode == OVPN_MODE_P2P) {
        switch (code) {
        // those IOCTLs are for MP mode
        case OVPN_IOCTL_MP_START_VPN:
        case OVPN_IOCTL_MP_NEW_PEER:
            return FALSE;
        }
    }

    return TRUE;
}

static NTSTATUS
OvpnStopVPN(_In_ POVPN_DEVICE device)
{
    LOG_ENTER();

    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
    PWSK_SOCKET socket = device->Socket.Socket;
    device->Socket.Socket = NULL;

    OvpnFlushPeers(device);

    device->Mode = OVPN_MODE_P2P;

    RtlZeroMemory(&device->Socket.TcpState, sizeof(OvpnSocketTcpState));
    RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));

    ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

    if (socket != NULL) {
        LOG_IF_NOT_NT_SUCCESS(OvpnSocketClose(socket));
    }

    // flush buffers in control queue so that client won't get control channel messages from previous session
    while (LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->ControlRxBufferQueue)) {
        OVPN_RX_BUFFER* buffer = CONTAINING_RECORD(entry, OVPN_RX_BUFFER, QueueListEntry);
        // return buffer back to pool
        OvpnRxBufferPoolPut(buffer);
    }

    WDFREQUEST request;
    while (NT_SUCCESS(WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request))) {
        ULONG_PTR bytesCopied = 0;
        LOG_INFO("Cancel IO request from manual queue");
        WdfRequestCompleteWithInformation(request, STATUS_CANCELLED, bytesCopied);
    }

    LOG_EXIT();

    return STATUS_SUCCESS;
}

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
OvpnMPStartVPN(POVPN_DEVICE device, WDFREQUEST request, ULONG_PTR* bytesReturned)
{
    NTSTATUS status = STATUS_SUCCESS;

    LOG_ENTER();

    KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
    if (device->Socket.Socket != NULL) {
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

        status = STATUS_ALREADY_INITIALIZED;

        goto done;
    }
    else {
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

        POVPN_MP_START_VPN addrIn = NULL;
        GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveInputBuffer(request, sizeof(OVPN_MP_START_VPN), (PVOID*)&addrIn, NULL));

        PWSK_SOCKET socket = NULL;
        POVPN_DRIVER driver = OvpnGetDriverContext(WdfGetDriver());

        // Bind to the address provided
        status = OvpnSocketInit(&driver->WskProviderNpi, &driver->WskRegistration,
            addrIn->ListenAddress.Addr4.sin_family, false,
            (PSOCKADDR)&addrIn->ListenAddress, NULL,
            0, device, &socket);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("Socket create failed", TraceLoggingValue((UINT32)status),
                TraceLoggingHexUInt32(*(UINT32*)(&addrIn->ListenAddress.Addr4.sin_addr), "addr"));
            goto done;
        }

        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        device->Socket.Socket = socket;
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

        // we might bind the socket to port 0 and we want to get actual port back to userspace
        POVPN_MP_START_VPN addrOut = NULL;
        GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveOutputBuffer(request, sizeof(OVPN_MP_START_VPN), (PVOID*)&addrOut, NULL));
        RtlCopyMemory(addrOut, addrIn, sizeof(OVPN_MP_START_VPN));
        *bytesReturned = sizeof(OVPN_MP_START_VPN);
    }

    OvpnAdapterSetLinkState(OvpnGetAdapterContext(device->Adapter), MediaConnectStateConnected);

done:
    LOG_EXIT();

    return status;
}

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL OvpnEvtIoDeviceControl;

_Use_decl_annotations_
VOID
OvpnEvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outputBufferLength, size_t inputBufferLength, ULONG ioControlCode) {
    UNREFERENCED_PARAMETER(outputBufferLength);
    UNREFERENCED_PARAMETER(inputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    ULONG_PTR bytesReturned = 0;

    if (!OvpnDeviceCheckMode(device->Mode, ioControlCode))
    {
        WdfRequestCompleteWithInformation(request, STATUS_INVALID_DEVICE_STATE, bytesReturned);
        return;
    }

    KIRQL kirql = 0;
    switch ((long)ioControlCode) {
    case OVPN_IOCTL_GET_STATS:
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
        status = OvpnPeerGetStats(device, request, &bytesReturned);
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_NEW_PEER:
        status = OvpnPeerNew(device, request);
        break;

    case OVPN_IOCTL_DEL_PEER:
        status = OvpnStopVPN(device);
        break;

    case OVPN_IOCTL_START_VPN:
        status = OvpnPeerStartVPN(device);
        break;

    case OVPN_IOCTL_NEW_KEY:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerNewKey(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_NEW_KEY_V2:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerNewKeyV2(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_SWAP_KEYS:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerSwapKeys(device);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_SET_PEER:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerSet(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_GET_VERSION:
        status = OvpnGetVersion(request, &bytesReturned);
        break;

    case OVPN_IOCTL_SET_MODE:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnSetMode(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_MP_START_VPN:
        status = OvpnMPStartVPN(device, request, &bytesReturned);
        break;

    case OVPN_IOCTL_MP_NEW_PEER:
        status = OvpnMPPeerNew(device, request);
        break;

    default:
        LOG_WARN("Unknown <ioControlCode>", TraceLoggingValue(ioControlCode, "ioControlCode"));
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    if (status != STATUS_PENDING) {
        WdfRequestCompleteWithInformation(request, status, bytesReturned);
    }
}

EVT_WDF_FILE_CLEANUP OvpnEvtFileCleanup;

_Use_decl_annotations_
VOID OvpnEvtFileCleanup(WDFFILEOBJECT fileObject) {
    LOG_ENTER();

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfFileObjectGetDevice(fileObject));

    (VOID)OvpnStopVPN(device);

    if (device->Adapter != NULL) {
        OvpnAdapterSetLinkState(OvpnGetAdapterContext(device->Adapter), MediaConnectStateDisconnected);
    }

    LOG_EXIT();
}

EVT_WDF_DEVICE_CONTEXT_CLEANUP OvpnEvtDeviceCleanup;

_Use_decl_annotations_
VOID OvpnEvtDeviceCleanup(WDFOBJECT obj) {
    LOG_ENTER();

    OVPN_DEVICE* device = OvpnGetDeviceContext(obj);

    OvpnTxBufferPoolDelete((OVPN_BUFFER_POOL)device->TxBufferPool);
    OvpnRxBufferPoolDelete((OVPN_BUFFER_POOL)device->RxBufferPool);

    OvpnBufferQueueDelete(device->ControlRxBufferQueue);
    OvpnBufferQueueDelete(device->DataRxBufferQueue);

    KIRQL irql = ExAcquireSpinLockExclusive(&device->SpinLock);
    device->Adapter = WDF_NO_HANDLE;
    ExReleaseSpinLockExclusive(&device->SpinLock, irql);

    // OvpnCryptoUninitAlgHandles called outside of lock because
    // it requires PASSIVE_LEVEL.
    OvpnCryptoUninitAlgHandles(device->AesAlgHandle, device->ChachaAlgHandle);

    // delete control device if there are no devices left
    POVPN_DRIVER driverCtx = OvpnGetDriverContext(WdfGetDriver());
    LONG deviceCount = InterlockedDecrement(&driverCtx->DeviceCount);
    LOG_INFO("Device count", TraceLoggingValue(deviceCount, "deviceCount"));
    if ((deviceCount == 0) && (driverCtx->ControlDevice != NULL)) {
        LOG_INFO("Delete control device");
        WdfObjectDelete(driverCtx->ControlDevice);
        driverCtx->ControlDevice = NULL;
    }
    LOG_EXIT();
}

EVT_WDF_DEVICE_PREPARE_HARDWARE OvpnEvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE OvpnEvtDeviceReleaseHardware;
_No_competing_thread_ EVT_WDF_DEVICE_D0_ENTRY OvpnEvtDeviceD0Entry;
_No_competing_thread_ EVT_WDF_DEVICE_D0_EXIT OvpnEvtDeviceD0Exit;

_Use_decl_annotations_
NTSTATUS
OvpnEvtDevicePrepareHardware(_In_ WDFDEVICE wdfDevice, _In_ WDFCMRESLIST resourcesRaw, _In_ WDFCMRESLIST resourcesTranslated)
{
    UNREFERENCED_PARAMETER(wdfDevice);
    UNREFERENCED_PARAMETER(resourcesRaw);
    UNREFERENCED_PARAMETER(resourcesTranslated);

    LOG_ENTER();
    LOG_EXIT();
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnEvtDeviceReleaseHardware(_In_ WDFDEVICE wdfDevice, _In_ WDFCMRESLIST resourcesTranslated)
{
    UNREFERENCED_PARAMETER(wdfDevice);
    UNREFERENCED_PARAMETER(resourcesTranslated);

    LOG_ENTER();
    LOG_EXIT();
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnEvtDeviceD0Entry(_In_ WDFDEVICE wdfDevice, WDF_POWER_DEVICE_STATE previousState)
{
    UNREFERENCED_PARAMETER(wdfDevice);

    LOG_ENTER(TraceLoggingUInt32(previousState, "PreviousState"));

    LOG_EXIT();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnEvtDeviceD0Exit(_In_ WDFDEVICE Device, _In_ WDF_POWER_DEVICE_STATE TargetState)
{
    UNREFERENCED_PARAMETER(Device);

    LOG_ENTER(TraceLoggingUInt32(TargetState, "TargetState"));

    LOG_EXIT();
    return STATUS_SUCCESS;
}

EVT_WDF_DRIVER_DEVICE_ADD OvpnEvtDeviceAdd;

_Use_decl_annotations_
NTSTATUS
OvpnEvtDeviceAdd(WDFDRIVER wdfDriver, PWDFDEVICE_INIT deviceInit) {
    UNREFERENCED_PARAMETER(wdfDriver);

    LOG_ENTER();

    // make sure only one app can access driver at time
    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, OvpnEvtFileCleanup);

    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    DECLARE_CONST_UNICODE_STRING(symLink, L"\\DosDevices\\ovpn-dco");

    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, NetDeviceInitConfig(deviceInit));

    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware = OvpnEvtDevicePrepareHardware;
    pnpPowerCallbacks.EvtDeviceReleaseHardware = OvpnEvtDeviceReleaseHardware;
    pnpPowerCallbacks.EvtDeviceD0Entry = OvpnEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit = OvpnEvtDeviceD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(deviceInit, &pnpPowerCallbacks);

    WDF_OBJECT_ATTRIBUTES objAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&objAttributes, OVPN_DEVICE);
    // BCryptOpenAlgorithmProvider with BCRYPT_PROV_DISPATCH returns STATUS_NOT_SUPPORTED if sync scope is WdfSynchronizationScopeDevice
    objAttributes.SynchronizationScope = WdfSynchronizationScopeNone;
    objAttributes.EvtCleanupCallback = OvpnEvtDeviceCleanup;

    WDFDEVICE wdfDevice;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreate(&deviceInit, &objAttributes, &wdfDevice));

    POVPN_DRIVER driverCtx = OvpnGetDriverContext(WdfGetDriver());
    InterlockedIncrement(&driverCtx->DeviceCount);

    LOG_INFO("Device count", TraceLoggingValue(driverCtx->DeviceCount, "count"));

    if (driverCtx->DeviceCount == 1)
    {
        // create non-exclusive control device to get the version information
        GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCreateControlDevice(wdfDriver));
    }

    // this will fail if one device has already been created but that's ok, since
    // openvpn2/3 accesses devices via Device Interface GUID, and symlink is used only by test client.
    LOG_IF_NOT_NT_SUCCESS(WdfDeviceCreateSymbolicLink(wdfDevice, &symLink));

    UNICODE_STRING referenceString;
    RtlInitUnicodeString(&referenceString, L"ovpn-dco");
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreateDeviceInterface(wdfDevice, &GUID_DEVINTERFACE_NET, &referenceString));

    // create main queue which handles reads/writes from userspace
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoRead = OvpnEvtIoRead;
    queueConfig.EvtIoWrite = OvpnEvtIoWrite;
    queueConfig.EvtIoDeviceControl = OvpnEvtIoDeviceControl;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE));

    POVPN_DEVICE device = OvpnGetDeviceContext(wdfDevice);
    device->WdfDevice = wdfDevice;

    // create manual pending queue which handles async reads
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingReadsQueue));

    // create manual pending queue which handles async writes
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingWritesQueue));

    // create manual pending queue which handles async NewPeer requests (when proto is TCP, connect is async)
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingNewPeerQueue));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnTxBufferPoolCreate(&device->TxBufferPool, device));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnRxBufferPoolCreate(&device->RxBufferPool));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnBufferQueueCreate(&device->ControlRxBufferQueue));
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnBufferQueueCreate(&device->DataRxBufferQueue));

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoInitAlgHandles(&device->AesAlgHandle, &device->ChachaAlgHandle));

    // Initialize peers tables
    RtlInitializeGenericTable(&device->Peers, OvpnPeerCompareByPeerIdRoutine, OvpnPeerAllocateRoutine, OvpnPeerFreeRoutine, NULL);
    RtlInitializeGenericTable(&device->PeersByVpn4, OvpnPeerCompareByVPN4Routine, OvpnPeerAllocateRoutine, OvpnPeerFreeRoutine, NULL);
    RtlInitializeGenericTable(&device->PeersByVpn6, OvpnPeerCompareByVPN6Routine, OvpnPeerAllocateRoutine, OvpnPeerFreeRoutine, NULL);

    LOG_IF_NOT_NT_SUCCESS(status = OvpnAdapterCreate(device));

done:
    LOG_EXIT();

    return status;
}

NTSTATUS
OvpnAddPeerToTable(_In_ RTL_GENERIC_TABLE* table, _In_ OvpnPeerContext* peer)
{
    NTSTATUS status;
    BOOLEAN newElem;

    RtlInsertElementGenericTable(table, (PVOID)&peer, sizeof(OvpnPeerContext*), &newElem);

    if (newElem) {
        status = STATUS_SUCCESS;
        InterlockedIncrement(&peer->RefCounter);
    }
    else {
        LOG_ERROR("Unable to add new peer");
        status = STATUS_NO_MEMORY;
    }
    return status;
}


_Use_decl_annotations_
NTSTATUS
OvpnAddPeer(POVPN_DEVICE device, OvpnPeerContext* peer)
{
    return OvpnAddPeerToTable(&device->Peers, peer);
}

_Use_decl_annotations_
NTSTATUS
OvpnAddPeerVpn4(POVPN_DEVICE device, OvpnPeerContext* peer)
{
    return OvpnAddPeerToTable(&device->PeersByVpn4, peer);
}

_Use_decl_annotations_
NTSTATUS
OvpnAddPeerVpn6(POVPN_DEVICE device, OvpnPeerContext* peer)
{
    return OvpnAddPeerToTable(&device->PeersByVpn6, peer);
}

_Use_decl_annotations_
VOID
OvpnFlushPeers(POVPN_DEVICE device) {
    OvpnCleanupPeerTable(&device->PeersByVpn6);
    OvpnCleanupPeerTable(&device->PeersByVpn4);
    OvpnCleanupPeerTable(&device->Peers);
}

_Use_decl_annotations_
VOID
OvpnCleanupPeerTable(RTL_GENERIC_TABLE* peers)
{
    while (!RtlIsGenericTableEmpty(peers)) {
        PVOID ptr = RtlGetElementGenericTable(peers, 0);
        OvpnPeerContext* peer = *(OvpnPeerContext**)ptr;
        RtlDeleteElementGenericTable(peers, ptr);

        if (InterlockedDecrement(&peer->RefCounter) == 0) {
            OvpnPeerCtxFree(peer);
        }
    }
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnGetFirstPeer(RTL_GENERIC_TABLE* peers)
{
    OvpnPeerContext** ptr = (OvpnPeerContext**)RtlGetElementGenericTable(peers, 0);
    return ptr ? (OvpnPeerContext*)*ptr : NULL;
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnFindPeer(POVPN_DEVICE device, INT32 PeerId)
{
    if (device->Mode == OVPN_MODE_P2P) {
        return OvpnGetFirstPeer(&device->Peers);
    }

    OvpnPeerContext p {};
    p.PeerId = PeerId;

    auto* pp = &p;
    OvpnPeerContext** ptr = (OvpnPeerContext**)RtlLookupElementGenericTable(&device->Peers, &pp);
    return ptr ? (OvpnPeerContext*)*ptr : NULL;
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnFindPeerVPN4(POVPN_DEVICE device, IN_ADDR addr)
{
    if (device->Mode == OVPN_MODE_P2P) {
        return OvpnGetFirstPeer(&device->Peers);
    }

    OvpnPeerContext p{};
    p.VpnAddrs.IPv4 = addr;

    auto* pp = &p;
    OvpnPeerContext** ptr = (OvpnPeerContext**)RtlLookupElementGenericTable(&device->PeersByVpn4, &pp);
    return ptr ? (OvpnPeerContext*)*ptr : NULL;
}

_Use_decl_annotations_
OvpnPeerContext*
OvpnFindPeerVPN6(POVPN_DEVICE device, IN6_ADDR addr)
{
    if (device->Mode == OVPN_MODE_P2P) {
        return OvpnGetFirstPeer(&device->Peers);
    }

    OvpnPeerContext p{};
    p.VpnAddrs.IPv6 = addr;

    auto* pp = &p;
    OvpnPeerContext** ptr = (OvpnPeerContext**)RtlLookupElementGenericTable(&device->PeersByVpn6, &pp);
    return ptr ? (OvpnPeerContext*)*ptr : NULL;
}
