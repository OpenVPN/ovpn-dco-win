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

#include "trie.h"

#include "trace.h"
#include "peer.h"

class IPTrie::TrieNode {
public:
    TrieNode* children[2];  // Two branches: 0 and 1
    OvpnPeerContext* peer;  // Associated peer context (if this is a valid prefix)
    bool isRoute;           // Marks if this node represents a valid route

    TrieNode() : peer(nullptr), isRoute(false) {
        children[0] = nullptr;
        children[1] = nullptr;
    }

    static TrieNode* AllocateNode() {
        TrieNode* node = (TrieNode*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TrieNode), 'ovpn');
        if (node) {
            RtlZeroMemory(node, sizeof(TrieNode));
        }
        return node;
    }

    static void FreeNode(TrieNode* node) {
        if (node) {
            ExFreePoolWithTag(node, 'ovpn');
        }
    }
};

VOID
IPTrie::Init(BOOLEAN isIPv6) {
    maxBits = isIPv6 ? 128 : 32;
    root = nullptr;
}

VOID
IPTrie::FreeTrie(TrieNode* node) {
    if (!node) return;
    if (node->children[0]) FreeTrie(node->children[0]);
    if (node->children[1]) FreeTrie(node->children[1]);
    TrieNode::FreeNode(node);
}

VOID
IPTrie::Cleanup() {
    LOG_ENTER();

    KIRQL oldIrql;
    LIST_ENTRY cleanupList;
    InitializeListHead(&cleanupList);

    oldIrql = ExAcquireSpinLockExclusive(&Lock);

    if (root) {
        CleanupNode(root, &cleanupList);
        root = nullptr; // Reset the root after cleaning up
    }

    ExReleaseSpinLockExclusive(&Lock, oldIrql);

    // Perform deferred cleanup of peers outside the lock
    PLIST_ENTRY entry;
    while (!IsListEmpty(&cleanupList)) {
        entry = RemoveHeadList(&cleanupList);
        OvpnPeerContext* peer = CONTAINING_RECORD(entry, OvpnPeerContext, ListEntry);
        OvpnPeerCtxRelease(peer);
    }

    LOG_EXIT();
}

VOID IPTrie::CleanupNode(TrieNode* node, PLIST_ENTRY cleanupList) {
    if (!node) return;

    CleanupNode(node->children[0], cleanupList);
    CleanupNode(node->children[1], cleanupList);

    if (node->peer) {
        InsertTailList(cleanupList, &node->peer->ListEntry);
        node->peer = nullptr;
    }

    TrieNode::FreeNode(node);
}

NTSTATUS
IPTrie::Insert(const UCHAR* ip, int prefixLength, OvpnPeerContext* peer) {
    LOG_ENTER();

    NTSTATUS status = STATUS_SUCCESS;

    KIRQL kirql = ExAcquireSpinLockExclusive(&Lock);

    if (!root) {
        root = TrieNode::AllocateNode();
        if (!root) {
            ExReleaseSpinLockExclusive(&Lock, kirql);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }
    }

    TrieNode* current = root;
    for (int i = 0; i < prefixLength && i < maxBits; ++i) {
        int bit = (ip[i / 8] >> (7 - (i % 8))) & 1;
        if (!current->children[bit]) {
            current->children[bit] = TrieNode::AllocateNode();
            if (!current->children[bit]) {
                ExReleaseSpinLockExclusive(&Lock, kirql);
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto done;
            }
        }
        current = current->children[bit];
    }

    // update the node with the peer info
    current->peer = peer;
    current->isRoute = true;

    // increment peer refcnt since it has been stored in a trie
    InterlockedIncrement(&peer->RefCounter);

    ExReleaseSpinLockExclusive(&Lock, kirql);

done:
    LOG_EXIT();
    return status;
}

OvpnPeerContext*
IPTrie::Find(const UCHAR* ip) {
    if (!root) return nullptr;

    KIRQL kirql = ExAcquireSpinLockShared(&Lock);

    TrieNode* current = root;
    OvpnPeerContext* peer = nullptr;
    for (int i = 0; i < maxBits && current; ++i) {
        if (current->isRoute) {
            peer = current->peer;
        }
        // Calculate the next bit of the IP address
        int bit = (ip[i / 8] >> (7 - (i % 8))) & 1;
        current = current->children[bit];
    }

    ExReleaseSpinLockShared(&Lock, kirql);

    // before returning the peer, increment refcnt
    if (peer) {
        InterlockedIncrement(&peer->RefCounter);
    }

    return peer;
}

VOID
IPTrie::RemoveByPeerId(INT32 peerId) {
    LOG_ENTER();

    LIST_ENTRY cleanupList;
    InitializeListHead(&cleanupList);

    // collect nodes to be deleted into the list
    KIRQL oldIrql = ExAcquireSpinLockExclusive(&Lock);
    root = RemoveByPeerId(root, peerId, &cleanupList);
    ExReleaseSpinLockExclusive(&Lock, oldIrql);

    // perform cleanup outside of the lock
    PLIST_ENTRY entry;
    while (!IsListEmpty(&cleanupList)) {
        entry = RemoveHeadList(&cleanupList);
        OvpnPeerContext* peer = CONTAINING_RECORD(entry, OvpnPeerContext, ListEntry);
        OvpnPeerCtxRelease(peer);
    }

    LOG_EXIT();
}

IPTrie::TrieNode*
IPTrie::RemoveByPeerId(TrieNode* node, INT32 peerId, PLIST_ENTRY cleanupList) {
    if (!node) return nullptr;

    // Recursively process left and right children
    node->children[0] = RemoveByPeerId(node->children[0], peerId, cleanupList);
    node->children[1] = RemoveByPeerId(node->children[1], peerId, cleanupList);

    // Check if this node's peer matches the target peerId
    if (node->peer && node->peer->PeerId == peerId) {
        // Defer the cleanup by adding the peer to the cleanup list
        InsertTailList(cleanupList, &node->peer->ListEntry);
        node->peer = nullptr;
        node->isRoute = false;
    }

    // If this node has no children and is no longer a route, delete it
    if (!node->children[0] && !node->children[1] && !node->isRoute) {
        TrieNode::FreeNode(node);
        return nullptr;
    }

    return node;
}

NTSTATUS
IPTrie::Remove(const UCHAR* ip, int prefixLength) {
    if (prefixLength < 0 || prefixLength > maxBits) {
        return STATUS_INVALID_PARAMETER;
    }

    OvpnPeerContext* peerToRelease = nullptr;

    KIRQL oldIrql = ExAcquireSpinLockExclusive(&Lock);
    root = RemoveRouteNode(root, ip, prefixLength, &peerToRelease);
    ExReleaseSpinLockExclusive(&Lock, oldIrql);

    // Release the peer outside the lock if needed
    if (peerToRelease) {
        OvpnPeerCtxRelease(peerToRelease);
    }

    return STATUS_SUCCESS;
}

IPTrie::TrieNode*
IPTrie::RemoveRouteNode(TrieNode* node, const UCHAR* ip, int prefixLength, OvpnPeerContext** peerToRelease) {
    if (!node) return nullptr;

    if (prefixLength > 0) {
        int bit = (ip[(maxBits - prefixLength) / 8] >> (7 - ((maxBits - prefixLength) % 8))) & 1;
        node->children[bit] = RemoveRouteNode(node->children[bit], ip, prefixLength - 1, peerToRelease);
    }
    else {
        if (node->peer) {
            *peerToRelease = node->peer;
            node->peer = nullptr;
        }
        node->isRoute = false;
    }

    // Cleanup: If the node has no children and is not a route, delete it
    if (!node->children[0] && !node->children[1] && !node->isRoute) {
        TrieNode::FreeNode(node);
        return nullptr;
    }

    return node;
}
