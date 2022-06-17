/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2022 OpenVPN Inc <sales@openvpn.net>
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

#include <wdm.h>
#include <netiodef.h>

#include "mss.h"
#include "trace.h"

BOOLEAN
OvpnMssIsIPv4(_In_ UCHAR* buf, SIZE_T len)
{
    if (len < sizeof(IPV4_HEADER))
        return FALSE;

    IPV4_HEADER* hdr = (IPV4_HEADER*)buf;
    return hdr->Version == IPV4_VERSION;
}

BOOLEAN
OvpnMssIsIPv6(_In_ UCHAR* buf, SIZE_T len)
{
    if (len < sizeof(IPV6_HEADER))
        return FALSE;

    IPV6_HEADER* hdr = (IPV6_HEADER*)buf;
    return hdr->Version == 6;
}

/*
 * The following macro is used to update an
 * internet checksum.  "acc" is a 32-bit
 * accumulation of all the changes to the
 * checksum (adding in old 16-bit words and
 * subtracting out new words), and "cksum"
 * is the checksum value to be updated.
 */
#define ADJUST_CHECKSUM(acc, cksum) { \
    int _acc = acc; \
    _acc += (cksum); \
    if (_acc < 0) { \
        _acc = -_acc; \
        _acc = (_acc >> 16) + (_acc & 0xffff); \
        _acc += _acc >> 16; \
        (cksum) = (UINT16) ~_acc; \
    } else { \
        _acc = (_acc >> 16) + (_acc & 0xffff); \
        _acc += _acc >> 16; \
        (cksum) = (UINT16) _acc; \
    } \
}

static
VOID
OvpnMssDoWork(_In_ UCHAR* buf, SIZE_T len, UINT16 maxmss)
{
    if (len < sizeof(TCP_HDR))
        return;

    TCP_HDR* th = (TCP_HDR*)buf;
    SIZE_T hlen = (SIZE_T)th->th_len << 2;

    // header without options or invalid header len
    if ((hlen <= sizeof(TCP_HDR)) || (hlen > len))
        return;

    SIZE_T olen, optlen;
    UCHAR* opt;
    for (olen = hlen - sizeof(TCP_HDR),
        opt = (UCHAR*)(th + 1);
        olen > 1;
        olen -= optlen, opt += optlen) {
        if (*opt == TH_OPT_EOL) {
            break;
        }
        else if (*opt == TH_OPT_NOP) {
            optlen = 1;
        } else {
            optlen = *(opt + 1);
            if (optlen <= 0 || optlen > olen) {
                break;
            }
            if (*opt == TH_OPT_MSS) {
                if (optlen != sizeof(TCP_OPT_MSS)) {
                    continue;
                }
                TCP_OPT_MSS* opt_mss = (TCP_OPT_MSS*)opt;
                UINT16 mssval = RtlUshortByteSwap(opt_mss->Mss);
                if (mssval > maxmss) {
                    // LOG_INFO("Adjust MSS", TraceLoggingValue(mssval, "old"), TraceLoggingValue(maxmss, "new"));
                    int accumulate = opt_mss->Mss;
                    opt_mss->Mss = RtlUshortByteSwap(maxmss);
                    accumulate -= RtlUshortByteSwap(maxmss);
                    ADJUST_CHECKSUM(accumulate, th->th_sum);
                }
            }
        }
    }
}

VOID
OvpnMssDoIPv4(_In_ UCHAR* buf, SIZE_T len, UINT16 mss)
{
    if (mss == 0) {
        return;
    }

    IPV4_HEADER* ipv4_hdr = (IPV4_HEADER*)buf;
    SIZE_T hlen = (SIZE_T)ipv4_hdr->HeaderLength << 2;

    if (ipv4_hdr->Protocol == IPPROTO_TCP
        && RtlUshortByteSwap(ipv4_hdr->TotalLength) == len
        && RtlUshortByteSwap(ipv4_hdr->FlagsAndOffset & IP4_OFF_MASK) == 0
        && hlen <= len
        && len - hlen >= sizeof(TCP_HDR))
    {
        buf += hlen;
        len -= hlen;
        TCP_HDR* tcp_hdr = (TCP_HDR*)buf;
        if (tcp_hdr->th_flags & TH_SYN) {
            OvpnMssDoWork(buf, len, mss);
        }
    }
}

VOID
OvpnMssDoIPv6(_In_ UCHAR* buf, SIZE_T len, UINT16 mss)
{
    if (mss == 0) {
        return;
    }

    IPV6_HEADER* ipv6_hdr = (IPV6_HEADER*)buf;

    // do we have full ipv6 packet?
    if (len != RtlUshortByteSwap(ipv6_hdr->PayloadLength) + sizeof(IPV6_HEADER)) {
        return;
    }

    if (ipv6_hdr->NextHeader != IPPROTO_TCP) {
        return;
    }

    buf += sizeof(IPV6_HEADER);
    len -= sizeof(IPV6_HEADER);

    TCP_HDR* tcp_hdr = (TCP_HDR*)buf;
    if (tcp_hdr->th_flags & TH_SYN) {
        OvpnMssDoWork(buf, len, mss - 20);
    }
}
