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

#include <ntddk.h>
#include <wsk.h>

#include "adapter.h"
#include "crypto.h"
#include "driver.h"
#include "mss.h"
#include "trace.h"
#include "rxqueue.h"
#include "timer.h"
#include "socket.h"
#include "peer.h"

IO_COMPLETION_ROUTINE OvpnSocketSyncOpCompletionRoutine;

_Use_decl_annotations_
NTSTATUS
OvpnSocketSyncOpCompletionRoutine(PDEVICE_OBJECT reserved, PIRP irp, PVOID context)
{
    UNREFERENCED_PARAMETER(reserved);
    UNREFERENCED_PARAMETER(irp);

    if (context != NULL)
        KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

template <class OP, class SUCCESS>
__forceinline static NTSTATUS
_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
OvpnSocketSyncOp(_In_z_ CHAR* opName, OP op, SUCCESS success)
{
    PIRP irp; // used for async completion
    KEVENT event; // used to wait for pending create operation
    NTSTATUS status;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoAllocateIrp(1, FALSE);
    if (!irp) {
        LOG_ERROR("IoAllocateIrp failed");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    IoSetCompletionRoutine(irp, OvpnSocketSyncOpCompletionRoutine, &event, TRUE, TRUE, TRUE);

    status = op(irp);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("<op> failed with status <status>", TraceLoggingValue(opName, "op"), TraceLoggingNTStatus(status, "status"));
        IoFreeIrp(irp);
        goto done;
    }

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("<op> error after wait, irp->IoStatus.status = <status>", TraceLoggingValue(opName, "op"), TraceLoggingNTStatus(status, "status"));
            IoFreeIrp(irp);
            goto done;
        }
    }

    success(irp);

    IoFreeIrp(irp);

done:
    return status;
}

static
VOID
OvpnSocketControlPacketReceived(_In_ POVPN_DEVICE device, _In_reads_(len) PUCHAR buf, SIZE_T len, _In_opt_ PSOCKADDR remote)
{
    SIZE_T hdrLen = 0, totalLen = len;

    // in UDP and MP mode we prepend CC packet with remote sockaddr before pushing it to userspace
    if (device->Mode == OVPN_MODE_MP && remote != NULL) {
        switch (remote->sa_family) {
        case AF_INET:
            hdrLen = sizeof(SOCKADDR_IN);
            break;

        case AF_INET6:
            hdrLen = sizeof(SOCKADDR_IN6);
            break;

        default:
            LOG_ERROR("Invalid remote address family", TraceLoggingValue(remote->sa_family, "AF"));
            InterlockedIncrementNoFence(&device->Stats.LostInControlPackets);
            return;
        }
        totalLen += hdrLen;
    }

    // fast path: hand the packet to a parked read; no lock needed, we queue nothing
    WDFREQUEST request;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request);
    if (NT_SUCCESS(status)) {
        // service IO request right away
        PVOID readBuffer;
        size_t readBufferLength;

        ULONG_PTR bytesSent = totalLen;

        LOG_IF_NOT_NT_SUCCESS(status = WdfRequestRetrieveOutputBuffer(request, totalLen, &readBuffer, &readBufferLength));
        if (NT_SUCCESS(status)) {

            if (hdrLen > 0) {
                // prepend with sockaddr
                RtlCopyMemory(readBuffer, remote, hdrLen);
            }

            // copy control packet payload
            RtlCopyMemory((PCHAR)readBuffer + hdrLen, buf, totalLen - hdrLen);

            InterlockedIncrementNoFence(&device->Stats.ReceivedControlPackets);
        } else {
            InterlockedIncrementNoFence(&device->Stats.LostInControlPackets);

            if (status == STATUS_BUFFER_TOO_SMALL) {
                LOG_ERROR("Buffer too small, packet len <pktlen>, buf len <buflen>",
                    TraceLoggingValue(totalLen, "pktlen"), TraceLoggingValue(readBufferLength, "buflen"));
            }

            bytesSent = 0;
        }

        WdfRequestCompleteWithInformation(request, status, bytesSent);

        return;
    }

    OVPN_RX_BUFFER* buffer;

    // fetch buffer
    if (!NT_SUCCESS(OvpnRxBufferPoolGet(device->RxBufferPool, &buffer))) {
        LOG_ERROR("RxBufferPool exhausted");
        InterlockedIncrementNoFence(&device->Stats.LostInControlPackets);
        return;
    }

    if (totalLen > OVPN_SOCKET_RX_PACKET_BUFFER_SIZE) {
        LOG_ERROR("Buffer too small, packet len <pktlen>, buf len <buflen>",
            TraceLoggingValue(totalLen, "pktlen"), TraceLoggingValue(sizeof(buffer->Data), "buflen"));

        OvpnRxBufferPoolPut(buffer);
        return;
    }

    if (hdrLen > 0) {
        // prepend with sockaddr
        RtlCopyMemory(OvpnBufferPut(buffer, hdrLen), remote, hdrLen);
    }

    // copy control packet payload
    RtlCopyMemory(OvpnBufferPut(buffer, len), buf, len);

    // paired with OvpnEvtIoRead(): the retrieve and enqueue must be atomic against it
    KIRQL irql = ExAcquireSpinLockExclusive(&device->ControlRxLock);
    status = WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request);
    if (!NT_SUCCESS(status)) {
        // enqueue buffer, it will be dequeued when read request arrives
        OvpnBufferQueueEnqueue(device->ControlRxBufferQueue, &buffer->QueueListEntry);
    }
    ExReleaseSpinLockExclusive(&device->ControlRxLock, irql);

    if (NT_SUCCESS(status)) {
        LOG_INFO("Serving a read request that raced control packet queueing");

        OvpnCompleteReadFromRxBuffer(device, request, buffer);
    }
}

static
VOID OvpnSocketDataPacketReceived(_In_ POVPN_DEVICE device, UCHAR op, UINT32 peerId, _In_reads_(len) PUCHAR cipherTextBuf, SIZE_T len, BOOLEAN dpc, _In_opt_ PSOCKADDR remoteAddr)
{
    InterlockedExchangeAddNoFence64(&device->Stats.TransportBytesReceived, len);

    OvpnPeerContext* peer = OvpnFindPeer(device, peerId, dpc);
    if (peer == nullptr) {
        LOG_WARN("Peer not found", TraceLoggingValue(peerId, "peerId"));
        InterlockedIncrementNoFence(&device->Stats.LostInDataPackets);
        return;
    }

    InterlockedExchangeAddNoFence64(&peer->LinkRxBytes, len);

    OVPN_RX_BUFFER* buffer;

    // fetch buffer for plaintext
    NTSTATUS status = OvpnRxBufferPoolGet(device->RxBufferPool, &buffer);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("RxBufferPool exhausted");
        InterlockedIncrementNoFence(&device->Stats.LostInDataPackets);
        OvpnPeerCtxRelease(peer);
        return;
    }

    KIRQL kirql = OvpnAcquireSpinLock(dpc, &peer->SpinLock, FALSE);

    BOOLEAN exclusive = FALSE;

    OvpnCryptoContext* cryptoContext = &peer->CryptoContext;

    if (cryptoContext->Decrypt) {
        UCHAR keyId = OvpnCryptoKeyIdExtract(op);

        // extend data area in the buffer for plaintext and crypto overhead
        OvpnBufferPut(buffer, len);

        OvpnCryptoDecryptParams decryptParams = { keyId, cipherTextBuf, len, buffer->Data };
        status = OvpnCryptoCallWithRetry(peer, dpc, &exclusive, dpc ? nullptr : &kirql, OvpnCryptoInvokeDecrypt, &decryptParams);

        if (NT_SUCCESS(status)) {
            const OvpnCryptoPacketLayout layout = cryptoContext->Layout;

            OvpnBufferTrim(buffer, len - layout.TailLen);
            OvpnBufferPull(buffer, layout.FrontLen);
        }
    }
    else {
        status = STATUS_INVALID_DEVICE_STATE;

        // LOG_WARN("CryptoContext not yet initialized");
    }

    if (NT_SUCCESS(status)) {
        OvpnTimerResetRecv(peer->Timer);
    }
    else {
        OvpnRxBufferPoolPut(buffer);
    }

    auto mss = peer->MSS;

    OvpnReleaseSpinLock(dpc, kirql, &peer->SpinLock, exclusive);

    // decrypt failed - don't proceed
    if (!NT_SUCCESS(status)) {
        OvpnPeerCtxRelease(peer);
        return;
    }

    // check if peer has floated
    if ((remoteAddr != nullptr) && (device->Mode == OVPN_MODE_MP)) {
        LOG_IF_NOT_NT_SUCCESS(status = OvpnPeerHandleFloat(device, peer, remoteAddr, dpc));

        // don't inject packet into OS if float denied
        if (!NT_SUCCESS(status)) {

            // return plaintext buffer back to the pool
            OvpnRxBufferPoolPut(buffer);

            OvpnPeerCtxRelease(peer);
            return;
        }
    }

    // ping packet?
    if (OvpnTimerIsKeepaliveMessage(buffer->Data, buffer->Len)) {
        LOG_INFO("Ping received", TraceLoggingValue(peerId, "peer-id"));

        // no need to inject ping packet into OS, return buffer to the pool
        OvpnRxBufferPoolPut(buffer);
    }
    else {
        BOOLEAN drop = TRUE;
        OvpnPeerContext* lookup_peer = NULL;

        if (OvpnMssIsIPv4(buffer->Data, buffer->Len)) {
            // perform Reverse Path Filtering
            auto addr = ((IPV4_HEADER*)(buffer->Data))->SourceAddress;
            lookup_peer = OvpnFindPeerVPN4(device, addr, dpc);
            if (lookup_peer == nullptr) {
                lookup_peer = device->IRoutesIPV4.Find(reinterpret_cast<UCHAR*>(&addr));
            }
            if (lookup_peer == peer) {
                drop = FALSE;
                OvpnMssDoIPv4(buffer->Data, buffer->Len, mss);
            }
        }
        else if (OvpnMssIsIPv6(buffer->Data, buffer->Len)) {
            // perform Reverse Path Filtering
            auto addr = ((IPV6_HEADER*)(buffer->Data))->SourceAddress;
            lookup_peer = OvpnFindPeerVPN6(device, addr, dpc);
            if (lookup_peer == nullptr) {
                lookup_peer = device->IRoutesIPV6.Find(reinterpret_cast<UCHAR*>(&addr));
            }
            if (lookup_peer == peer) {
                drop = FALSE;
                OvpnMssDoIPv6(buffer->Data, buffer->Len, mss);
            }
        }

        if (lookup_peer) {
            OvpnPeerCtxRelease(lookup_peer);
        }

        if (!drop) {
            // enqueue plaintext buffer, it will be dequeued by NetAdapter RX datapath
            OvpnBufferQueueEnqueue(device->DataRxBufferQueue, &buffer->QueueListEntry);

            InterlockedExchangeAddNoFence64(&peer->VpnRxBytes, buffer->Len);

            OvpnAdapterNotifyRx(device->Adapter);
        } else {
            // packet is dropped due to RPF, return buffer to the pool
            OvpnRxBufferPoolPut(buffer);
        }
    }

    OvpnPeerCtxRelease(peer);
}

VOID
OvpnSocketProcessIncomingPacket(_In_ POVPN_DEVICE device, _In_reads_(packetLength) PUCHAR buf, SIZE_T packetLength, BOOLEAN irqlDispatch, _In_opt_ PSOCKADDR remoteAddr)
{
    if (packetLength < OVPN_DATA_V2_LEN) {
        LOG_ERROR("Packet too short", TraceLoggingValue(packetLength, "len"));
        return;
    }

    UCHAR op = RtlUlongByteSwap(*(ULONG*)(buf)) >> 24;
    if (OvpnCryptoOpcodeExtract(op) == OVPN_OP_DATA_V2) {
        UINT32 peerId = RtlUlongByteSwap(*(ULONG*)(buf)) & OVPN_PEER_ID_MASK;
        OvpnSocketDataPacketReceived(device, op, peerId, buf, packetLength, irqlDispatch, remoteAddr);
    }
    else {
        OvpnSocketControlPacketReceived(device, buf, packetLength, remoteAddr);
    }
}

_Must_inspect_result_
static
NTSTATUS
OvpnSocketUdpReceiveFromEvent(_In_ PVOID socketContext, ULONG flags, _In_opt_ PWSK_DATAGRAM_INDICATION dataIndication)
{
    POVPN_DEVICE device = (POVPN_DEVICE)socketContext;

    if (device->Socket.Socket == NULL) {
        LOG_ERROR("TransportSocket is not initialized");
        return STATUS_SUCCESS;
    }

    PUCHAR packetBuf = device->Socket.UdpState.PacketBuf;

    while (dataIndication != NULL) {
        PMDL mdl = dataIndication->Buffer.Mdl;
        ULONG offset = dataIndication->Buffer.Offset;
        SIZE_T length = dataIndication->Buffer.Length;

        if (mdl == NULL) {
            LOG_ERROR("WSK_DATAGRAM_INDICATION has NULL MDL");
            RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));
            dataIndication = dataIndication->Next;
            continue;
        }

        if (length > OVPN_SOCKET_RX_PACKET_BUFFER_SIZE) {
            LOG_ERROR("UDP datagram of size <size> is larger than buffer size <buf>",
                TraceLoggingValue(length, "size"),
                TraceLoggingValue(OVPN_SOCKET_RX_PACKET_BUFFER_SIZE, "buf"));
            RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));
            return STATUS_SUCCESS;
        }

        PUCHAR buf = NULL;

        if (mdl->Next == NULL) {
            // Fast path: datagram is fully contained in a single MDL
            buf = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);
            if (buf == NULL) {
                LOG_ERROR("MmGetSystemAddressForMdlSafe failed (non-fragmented)");
                RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));
                return STATUS_SUCCESS;
            }
            buf += offset;
        }
        else {
            // Slow path: reassemble fragmented datagram
            SIZE_T bytesRemained = length;
            SIZE_T bytesCopied = 0;
            PMDL currentMdl = mdl;
            ULONG currentOffset = offset;

            while (currentMdl && bytesRemained > 0) {
                PUCHAR mapped = (PUCHAR)MmGetSystemAddressForMdlSafe(currentMdl, LowPagePriority | MdlMappingNoExecute);
                if (mapped == NULL) {
                    LOG_ERROR("MmGetSystemAddressForMdlSafe failed (fragmented)");
                    RtlZeroMemory(&device->Socket.UdpState, sizeof(OvpnSocketUdpState));
                    return STATUS_SUCCESS;
                }

                mapped += currentOffset;
                SIZE_T copyLength = min(bytesRemained, MmGetMdlByteCount(currentMdl) - currentOffset);
                RtlCopyMemory(packetBuf + bytesCopied, mapped, copyLength);

                bytesCopied += copyLength;
                bytesRemained -= copyLength;

                currentOffset = 0;
                currentMdl = currentMdl->Next;
            }

            buf = packetBuf;
        }

        OvpnSocketProcessIncomingPacket(device, buf, length,
            flags & WSK_FLAG_AT_DISPATCH_LEVEL,
            dataIndication->RemoteAddress);

        dataIndication = dataIndication->Next;
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
OvpnSocketTcpReceiveEvent(_In_opt_ PVOID socketContext, _In_ ULONG flags, _In_opt_ PWSK_DATA_INDICATION dataIndication, _In_ SIZE_T bytesIndicated, _Inout_ SIZE_T* bytesAccepted)
{
    UNREFERENCED_PARAMETER(bytesAccepted);
    UNREFERENCED_PARAMETER(bytesIndicated);

    POVPN_DEVICE device = (POVPN_DEVICE)socketContext;

    OvpnSocketTcpState* tcpState = &device->Socket.TcpState;

    // iterate over data indications
    while (dataIndication != NULL) {
        PMDL mdl = dataIndication->Buffer.Mdl;
        ULONG offset = dataIndication->Buffer.Offset;
        SIZE_T dataIndicationLen = dataIndication->Buffer.Length;

        // iterate over MDLs
        while (dataIndicationLen > 0 && mdl != NULL) {
            SIZE_T mdlDataLen = min(dataIndicationLen, MmGetMdlByteCount(mdl) - offset);
            PUCHAR sysAddr = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);

            if (sysAddr == NULL) {
                RtlZeroMemory(tcpState, sizeof(OvpnSocketTcpState));
                return STATUS_SUCCESS;
            }
            sysAddr += offset;

            // there could be multiple packets inside MDL
            while (mdlDataLen > 0) {
                // have we already read packet length?
                if (tcpState->PacketLength == 0) {
                    // read packet length (or part of it)
                    USHORT packetLengthRead = (USHORT)min(mdlDataLen, sizeof(tcpState->LenBuf) - tcpState->BytesRead);
                    RtlCopyMemory(tcpState->LenBuf + tcpState->BytesRead, sysAddr, packetLengthRead);
                    tcpState->BytesRead += packetLengthRead;

                    // header fully read?
                    if (tcpState->BytesRead == sizeof(tcpState->LenBuf)) {
                        USHORT len = RtlUshortByteSwap(*(USHORT*)tcpState->LenBuf);
                        if ((len == 0) || (len > OVPN_SOCKET_RX_PACKET_BUFFER_SIZE)) {
                            LOG_ERROR("TCP <payload size> is 0 or larger than <buffer size>", TraceLoggingValue(len, "payload size"),
                                TraceLoggingValue(OVPN_SOCKET_RX_PACKET_BUFFER_SIZE, "buffer size"));
                            RtlZeroMemory(tcpState, sizeof(OvpnSocketTcpState));
                            return STATUS_SUCCESS;
                        }

                        tcpState->PacketLength = len;
                        tcpState->BytesRead = 0;
                    }

                    sysAddr += packetLengthRead;

                    mdlDataLen -= packetLengthRead;
                    dataIndicationLen -= packetLengthRead;
                }
                else {
                    // read packet content

                    SIZE_T bytesRemained = tcpState->PacketLength - tcpState->BytesRead;
                    BOOLEAN packetFitsIntoMDL = bytesRemained <= mdlDataLen;

                    if (packetFitsIntoMDL) {
                        PUCHAR buf;
                        if (tcpState->BytesRead == 0) {
                            // we haven't started reading packet and it fits into MDL, so process it in-place
                            buf = sysAddr;
                        }
                        else {
                            // copy rest of packet into buffer
                            RtlCopyMemory(tcpState->PacketBuf + tcpState->BytesRead, sysAddr, bytesRemained);
                            buf = tcpState->PacketBuf;
                        }

                        OvpnSocketProcessIncomingPacket(device, buf, tcpState->PacketLength, flags & WSK_FLAG_AT_DISPATCH_LEVEL, NULL);

                        mdlDataLen -= bytesRemained;
                        dataIndicationLen -= bytesRemained;
                        sysAddr += bytesRemained;

                        // get ready for next packet
                        tcpState->PacketLength = 0;
                        tcpState->BytesRead = 0;
                    }
                    else {
                        // payload doesn't fit into MDL, copy rest of MDL into buffer
                        RtlCopyMemory(tcpState->PacketBuf + tcpState->BytesRead, sysAddr, mdlDataLen);

                        tcpState->BytesRead += (USHORT)mdlDataLen;

                        dataIndicationLen -= mdlDataLen;
                        mdlDataLen = 0;
                    }
                }
            }

            offset = 0;
            mdl = mdl->Next;
        }

        dataIndication = dataIndication->Next;
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
OvpnSocketTcpDisconnectEvent(_In_opt_ PVOID socketContext, _In_ ULONG flags)
{
    UNREFERENCED_PARAMETER(flags);

    LOG_INFO("TCP disconnect");

    if (socketContext == NULL) {
        return STATUS_SUCCESS;
    }

    POVPN_DEVICE device = (POVPN_DEVICE)socketContext;

    // inform userspace about error
    WDFREQUEST request;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request);
    if (NT_SUCCESS(status)) {
        ULONG_PTR bytesCopied = 0;
        WdfRequestCompleteWithInformation(request, STATUS_CONNECTION_ABORTED, bytesCopied);
    }
    else {
        LOG_WARN("No pending read request, cannot inform userspace");
    }

    return STATUS_SUCCESS;
}

const WSK_CLIENT_DATAGRAM_DISPATCH OvpnSocketUdpDispatch = { OvpnSocketUdpReceiveFromEvent };
const WSK_CLIENT_CONNECTION_DISPATCH OvpnSocketTcpDispatch = { OvpnSocketTcpReceiveEvent, OvpnSocketTcpDisconnectEvent, NULL };

_Use_decl_annotations_
NTSTATUS
OvpnSocketInit(WSK_PROVIDER_NPI* wskProviderNpi, WSK_REGISTRATION* wskRegistration, ADDRESS_FAMILY addressFamily, BOOLEAN tcp, PSOCKADDR localAddr,
    PSOCKADDR remoteAddr, SIZE_T remoteAddrSize, PVOID deviceContext, PWSK_SOCKET* socket, BOOLEAN ipv6only)
{
    NTSTATUS status;
    WSK_EVENT_CALLBACK_CONTROL eventCallbackControl = {};

    // init WSK
    if (wskProviderNpi->Client == NULL) {
        LOG_INFO("Init WSK");
        GOTO_IF_NOT_NT_SUCCESS(done, status, WskCaptureProviderNPI(wskRegistration, WSK_INFINITE_WAIT, wskProviderNpi));
    }

    // create socket

    USHORT socketType = tcp ? SOCK_STREAM : SOCK_DGRAM;
    ULONG proto = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    ULONG flags = tcp ? WSK_FLAG_CONNECTION_SOCKET : WSK_FLAG_DATAGRAM_SOCKET;
    PVOID dispatch = tcp ? (PVOID)&OvpnSocketTcpDispatch : (PVOID)&OvpnSocketUdpDispatch;

    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnSocketSyncOp("CreateSocket", [&status, wskProviderNpi, addressFamily, socketType, proto, flags, deviceContext, dispatch](PIRP irp) {
        return wskProviderNpi->Dispatch->WskSocket(wskProviderNpi->Client, addressFamily, socketType, proto, flags, deviceContext,
            dispatch, NULL, NULL, NULL, irp);
        }, [socket](PIRP irp) {
            *socket = (PWSK_SOCKET)irp->IoStatus.Information;
        }
    ));

    PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)(*socket)->Dispatch;

    if (tcp) {
        // bind
        GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnSocketSyncOp("BindSocket", [connectionDispatch, socket, localAddr](PIRP irp) {
            return connectionDispatch->WskBind(*socket, localAddr, 0, irp);
        }, [](PIRP) {}));
    }
    else {
        PWSK_PROVIDER_BASIC_DISPATCH basicDispatch = (PWSK_PROVIDER_BASIC_DISPATCH)(*socket)->Dispatch;

        if (!ipv6only) {
            LOG_INFO("Enable dual-stack");
            // enable dual-stack
            LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketSyncOp("IPV6_V6ONLY", [basicDispatch, socket](PIRP irp) {
                ULONG ipv6Only = 0;
                return basicDispatch->WskControlSocket(*socket, WskSetOption, IPV6_V6ONLY, IPPROTO_IPV6, sizeof(ipv6Only), &ipv6Only, 0, NULL, NULL, irp);
                }, [](PIRP) {}));
        }

        // bind
        PWSK_PROVIDER_DATAGRAM_DISPATCH datagramDispatch = (PWSK_PROVIDER_DATAGRAM_DISPATCH)(*socket)->Dispatch;

        GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnSocketSyncOp("BindSocket", [datagramDispatch, socket, localAddr](PIRP irp) {
            return datagramDispatch->WskBind(*socket, localAddr, 0, irp);
        }, [](PIRP) {}));

        // get the locally bound address for the socket
        GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnSocketSyncOp("GetLocalAddr", [datagramDispatch, socket, localAddr](PIRP irp) {
            return datagramDispatch->WskGetLocalAddress(*socket, localAddr, irp);
        }, [](PIRP) {}));

        if (remoteAddr != NULL) {
            // set remote
            GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnSocketSyncOp("SetRemote", [basicDispatch, socket, remoteAddrSize, remoteAddr](PIRP irp) {
                return basicDispatch->WskControlSocket(*socket, WskIoctl, SIO_WSK_SET_REMOTE_ADDRESS, 0, remoteAddrSize, remoteAddr, 0, NULL, NULL, irp);
                }, [](PIRP) {}));
        }

        // enable ReceiveFrom event
        eventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
        eventCallbackControl.EventMask = WSK_EVENT_RECEIVE_FROM;

        GOTO_IF_NOT_NT_SUCCESS(error, status, connectionDispatch->Basic.WskControlSocket(*socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET,
            sizeof(WSK_EVENT_CALLBACK_CONTROL), &eventCallbackControl, 0, NULL, NULL, NULL));
    }

    goto done;

error:
    // ignore return value of CloseSocket
#pragma warning(suppress: 6031)
    OvpnSocketClose(*socket);
    *socket = NULL;

done:
    return status;
}

NTSTATUS
_Use_decl_annotations_
OvpnSocketClose(PWSK_SOCKET socket)
{
    if (socket == NULL) {
        return STATUS_SUCCESS;
    }

    NTSTATUS status;
    PWSK_PROVIDER_BASIC_DISPATCH dispatch = (PWSK_PROVIDER_BASIC_DISPATCH)socket->Dispatch;

    status = OvpnSocketSyncOp("CloseSocket", [dispatch, socket](PIRP irp) {
        return dispatch->WskCloseSocket(socket, irp);
    }, [](PIRP) { });

    return status;
}

_Function_class_(IO_COMPLETION_ROUTINE)
NTSTATUS
OvpnSocketTcpConnectComplete(_In_ PDEVICE_OBJECT deviceObj, _In_ PIRP irp, _In_ PVOID context)
{
    UNREFERENCED_PARAMETER(deviceObj);

    POVPN_DEVICE device = (POVPN_DEVICE)context;

    // finish pending IO request
    WDFREQUEST request;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(device->PendingNewPeerQueue, &request);

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("No pending NewPeer requests");
    }
    else {
        status = irp->IoStatus.Status;
        LOG_INFO("TCP Connect completed", TraceLoggingNTStatus(status, "status"));
        if (status == STATUS_SUCCESS) {
            WSK_EVENT_CALLBACK_CONTROL eventCallbackControl = {};
            // enable Receive and Disconnect events
            eventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
            eventCallbackControl.EventMask = WSK_EVENT_RECEIVE | WSK_EVENT_DISCONNECT;

            KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
            PWSK_SOCKET socket = device->Socket.Socket;
            ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

            if (socket != NULL) {
                PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)(socket)->Dispatch;
                LOG_IF_NOT_NT_SUCCESS(status = connectionDispatch->Basic.WskControlSocket(socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET,
                    sizeof(WSK_EVENT_CALLBACK_CONTROL), &eventCallbackControl, 0, NULL, NULL, NULL));
            }
            else {
                LOG_ERROR("socket is NULL");
                status = STATUS_INVALID_DEVICE_STATE;
            }

        }
        // complete request
        ULONG_PTR bytesSent = 0;
        WdfRequestCompleteWithInformation(request, status, bytesSent);
    }

    // Free the IRP
    IoFreeIrp(irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
_Use_decl_annotations_
OvpnSocketTcpConnect(PWSK_SOCKET socket, PVOID context, PSOCKADDR remote)
{
    // Get pointer to the socket's provider dispatch structure
    PWSK_PROVIDER_CONNECTION_DISPATCH dispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)(socket->Dispatch);

    // Allocate an IRP
    PIRP irp = IoAllocateIrp(1, FALSE);

    // Check result
    if (!irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(irp, OvpnSocketTcpConnectComplete, context, TRUE, TRUE, TRUE);

    LOG_INFO("TCP Connect initiated");

    // Initiate the connect operation on the socket
    return dispatch->WskConnect(socket, remote, 0, irp);
}

static
VOID
OvpnSocketFinalizeTxBuffer(_In_ OVPN_TX_BUFFER* buffer, NTSTATUS ioStatus, ULONG bytesSent)
{
    if (buffer->IoQueue != NULL) {
        WDFREQUEST request;
        NTSTATUS status;
        GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueRetrieveNextRequest(buffer->IoQueue, &request));

        // report status and bytesSent to userspace
        WdfRequestCompleteWithInformation(request, ioStatus, bytesSent);
    }

done:
    while (buffer != NULL) {
        OVPN_TX_BUFFER* next = (OVPN_TX_BUFFER*)buffer->WskBufList.Next;
        OvpnTxBufferPoolPut(buffer);
        buffer = next;
    }
}

_Function_class_(IO_COMPLETION_ROUTINE)
NTSTATUS
OvpnSocketSendComplete(_In_ PDEVICE_OBJECT deviceObj, _In_ PIRP irp, _In_ PVOID ctx)
{
    UNREFERENCED_PARAMETER(deviceObj);

    OVPN_TX_BUFFER* buffer = (OVPN_TX_BUFFER*)ctx;
    OVPN_DEVICE* device = (OVPN_DEVICE*)OvpnTxBufferPoolGetContext(buffer->Pool);
    ULONG bytesSend = (ULONG)(irp->IoStatus.Information);

    if (irp->IoStatus.Status != STATUS_SUCCESS) {
        LOG_ERROR("Send failed", TraceLoggingNTStatus(irp->IoStatus.Status, "status"));
    }
    else {
        if (buffer->IoQueue == NULL) {
            // this is data channel packet
            InterlockedExchangeAddNoFence64(&device->Stats.TransportBytesSent, bytesSend);
        }
    }

    if (device->Socket.Tcp)
        bytesSend -= 2;
    OvpnSocketFinalizeTxBuffer(buffer, irp->IoStatus.Status, bytesSend);

    IoFreeIrp(irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
_Use_decl_annotations_
OvpnSocketSend(OvpnSocket* ovpnSocket, OVPN_TX_BUFFER* buffer, SOCKADDR* sa) {
    OVPN_DEVICE* device = (OVPN_DEVICE*)OvpnTxBufferPoolGetContext(buffer->Pool);

    PWSK_SOCKET socket = ovpnSocket->Socket;

    PIRP irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) {
        LOG_ERROR("Failed to allocate IRP");
        OvpnSocketFinalizeTxBuffer(buffer, STATUS_INSUFFICIENT_RESOURCES, 0);
        InterlockedIncrementNoFence(buffer->IoQueue != WDF_NO_HANDLE ? &device->Stats.LostOutControlPackets : &device->Stats.LostOutDataPackets);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (socket == NULL) {
        LOG_ERROR("Socket is NULL");
        OvpnSocketFinalizeTxBuffer(buffer, STATUS_INVALID_DEVICE_STATE, 0);
        IoFreeIrp(irp);
        InterlockedIncrementNoFence(buffer->IoQueue != WDF_NO_HANDLE ? &device->Stats.LostOutControlPackets : &device->Stats.LostOutDataPackets);
        return STATUS_INVALID_DEVICE_STATE;
    }

    // completion routine will be called in any case and will free IRP
    IoSetCompletionRoutine(irp, OvpnSocketSendComplete, buffer, TRUE, TRUE, TRUE);

    // prepend TCP packet with size, as required by OpenVPN protocol
    if (ovpnSocket->Tcp) {
        UINT16 len = RtlUshortByteSwap(buffer->Len);
        *(UINT16*)OvpnTxBufferPush(buffer, 2) = len;
    }

    NTSTATUS status;
    if (ovpnSocket->Tcp) {
        WSK_BUF wskBuf{ buffer->Mdl, FIELD_OFFSET(OVPN_TX_BUFFER, Head) + (ULONG)(buffer->Data - buffer->Head), buffer->Len };
        PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch;
        LOG_IF_NOT_NT_SUCCESS(status = connectionDispatch->WskSend(socket, &wskBuf, WSK_FLAG_NODELAY, irp));
    }
    else if (buffer->WskBufList.Buffer.Length != 0) {
        PWSK_PROVIDER_DATAGRAM_DISPATCH datagramDispatch = (PWSK_PROVIDER_DATAGRAM_DISPATCH)socket->Dispatch;
        LOG_IF_NOT_NT_SUCCESS(status = datagramDispatch->WskSendMessages(socket, &buffer->WskBufList, 0, sa, 0, NULL, irp));
    } else {
        WSK_BUF wskBuf{ buffer->Mdl, FIELD_OFFSET(OVPN_TX_BUFFER, Head) + (ULONG)(buffer->Data - buffer->Head), buffer->Len };
        PWSK_PROVIDER_DATAGRAM_DISPATCH datagramDispatch = (PWSK_PROVIDER_DATAGRAM_DISPATCH)socket->Dispatch;
        LOG_IF_NOT_NT_SUCCESS(status = datagramDispatch->WskSendTo(socket, &wskBuf, 0, sa, 0, NULL, irp));
    }

    return status;
}
