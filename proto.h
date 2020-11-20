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

enum {
	// packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte
	OVPN_KEY_ID_MASK	= 0x07,
	OVPN_OPCODE_SHIFT	= 3,
	OVPN_OPCODE_MASK	= 0x1F,

	// packet opcodes of interest to us
	OVPN_DATA_V2		= 9, /* data channel V2 packet */

	/* size of initial packet opcode */
	OVPN_OP_SIZE_V2 = 4
};

static inline unsigned int OvpnProtoOpCompose(const unsigned int opcode, const unsigned int keyId)
{
	return (opcode << OVPN_OPCODE_SHIFT) | keyId;
}

static inline unsigned int OvpnProtoOp32Compose(const unsigned int opcode, const unsigned int keyId, const int opPeerId)
{
	const unsigned int op8 = OvpnProtoOpCompose(opcode, keyId);

	if (opcode == OVPN_DATA_V2)
		return (op8 << 24) | (opPeerId & 0x00FFFFFF);

	return op8;
}

static inline unsigned int OvpnProtoOpcodeExtract(const unsigned int op)
{
	return op >> OVPN_OPCODE_SHIFT;
}

static inline unsigned int OvpnProtoKeyIdExtract(unsigned int op)
{
	return op & OVPN_KEY_ID_MASK;
}

static inline bool OvpnProtoOpcodeIsDataV2(const unsigned int op)
{
	const unsigned int opcode = OvpnProtoOpcodeExtract(op);

	return opcode == OVPN_DATA_V2;
}
