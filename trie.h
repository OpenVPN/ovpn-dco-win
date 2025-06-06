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

struct OvpnPeerContext;

 // IPTrie interface
class IPTrie {
public:
    IPTrie() = delete;

    // Initialize the trie
    VOID Init(BOOLEAN isIPv6);

    // Insert a route into the trie
    NTSTATUS Insert(const UCHAR* ip, int prefixLength, OvpnPeerContext* peerContext);

    // Remove a route from the trie
    NTSTATUS Remove(const UCHAR* ip, int prefixLength);

    // Find the best match for a given IP address
    OvpnPeerContext* Find(const UCHAR* ip);

    // Remove all nodes associated with a specific peer-id
    VOID RemoveByPeerId(INT32 peerId);

    // Clean up the trie (explicitly called by the user)
    VOID Cleanup();

private:
    class TrieNode; // Forward declaration of TrieNode
    TrieNode* root; // Root of the trie
    int maxBits;   // Maximum number of bits (32 for IPv4, 128 for IPv6)

    EX_SPIN_LOCK Lock = 0; // Lock for shared/exclusive access

    TrieNode* RemoveByPeerId(TrieNode* node, INT32 peerId, PLIST_ENTRY cleanupList);
    TrieNode* RemoveRouteNode(TrieNode* node, const UCHAR* ip, int prefixLength, int depth, OvpnPeerContext** peerToRelease);

    VOID FreeTrie(TrieNode* node);
    VOID CleanupNode(TrieNode* node, PLIST_ENTRY cleanupList);
};