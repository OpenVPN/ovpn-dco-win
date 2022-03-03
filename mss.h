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

BOOLEAN
OvpnMssIsIPv4(_In_ UCHAR* buf, SIZE_T len);

VOID
OvpnMssDoIPv4(_In_ UCHAR* buf, SIZE_T len, UINT16 mss);

BOOLEAN
OvpnMssIsIPv6(_In_ UCHAR* buf, SIZE_T len);

VOID
OvpnMssDoIPv6(_In_ UCHAR* buf, SIZE_T len, UINT16 mss);
