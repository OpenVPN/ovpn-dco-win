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

    // Perform deferred cleanup of peers outside the lock. CleanupNode() has
    // already dropped the reference, so this is the free rather than a release.
    PLIST_ENTRY entry;
    while (!IsListEmpty(&cleanupList)) {
        entry = RemoveHeadList(&cleanupList);
        OvpnPeerContext* peer = CONTAINING_RECORD(entry, OvpnPeerContext, ListEntry);
        OvpnPeerCtxFree(peer);
    }

    LOG_EXIT();
}

VOID IPTrie::CleanupNode(TrieNode* node, PLIST_ENTRY cleanupList) {
    if (!node) return;

    CleanupNode(node->children[0], cleanupList);
    CleanupNode(node->children[1], cleanupList);

    if (node->peer) {
        // if we're last to hold a reference, defer the cleanup by adding the peer to the cleanup list
        if (InterlockedDecrement(&node->peer->RefCounter) == 0) {
            InsertTailList(cleanupList, &node->peer->ListEntry);
        }
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
    // keep track of any existing peer so we can release it outside the lock
    OvpnPeerContext* oldPeer = current->peer;
    current->peer = peer;
    current->isRoute = true;

    // increment peer refcnt since it has been stored in a trie
    InterlockedIncrement(&peer->RefCounter);

    LOG_INFO("Peer node", TraceLoggingValue(peer->PeerId, "peerId"));

    ExReleaseSpinLockExclusive(&Lock, kirql);

    // release the previous peer outside the lock if it existed
    if (oldPeer) {
        LOG_INFO("Release previous peer", TraceLoggingValue(oldPeer->PeerId, "peerId"));
        OvpnPeerCtxRelease(oldPeer);
    }

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

    if (current && current->isRoute) {
        peer = current->peer;
    }

    // Increment refcnt while still holding the lock. The trie node holds a
    // reference that is only dropped under the exclusive lock (RemoveByPeerId,
    // Remove, Cleanup), so the peer cannot be freed out from under us here.
    // Releasing the lock first would open a window for a concurrent peer
    // delete to drop the last reference and free the peer before the
    // increment lands.
    if (peer) {
        InterlockedIncrement(&peer->RefCounter);
    }

    ExReleaseSpinLockShared(&Lock, kirql);

    return peer;
}

VOID
IPTrie::RemoveByPeerId(INT32 peerId) {
    LIST_ENTRY cleanupList;
    InitializeListHead(&cleanupList);

    // collect nodes to be deleted into the list
    KIRQL oldIrql = ExAcquireSpinLockExclusive(&Lock);
    root = RemoveByPeerId(root, peerId, &cleanupList);
    ExReleaseSpinLockExclusive(&Lock, oldIrql);

    // perform cleanup outside of the lock. RemoveByPeerId() has already
    // dropped the reference, so this is the free rather than a release.
    PLIST_ENTRY entry;
    while (!IsListEmpty(&cleanupList)) {
        entry = RemoveHeadList(&cleanupList);
        OvpnPeerContext* peer = CONTAINING_RECORD(entry, OvpnPeerContext, ListEntry);
        OvpnPeerCtxFree(peer);
    }
}

IPTrie::TrieNode*
IPTrie::RemoveByPeerId(TrieNode* node, INT32 peerId, PLIST_ENTRY cleanupList) {
    if (!node) return nullptr;

    // Recursively process left and right children
    node->children[0] = RemoveByPeerId(node->children[0], peerId, cleanupList);
    node->children[1] = RemoveByPeerId(node->children[1], peerId, cleanupList);

    // Check if this node's peer matches the target peerId
    if (node->peer && node->peer->PeerId == peerId) {

        // if we're last to hold a reference, defer the cleanup by adding the peer to the cleanup list
        if (InterlockedDecrement(&node->peer->RefCounter) == 0) {
            InsertTailList(cleanupList, &node->peer->ListEntry);
        }

        node->peer = nullptr;
        node->isRoute = false;

        LOG_INFO("Peer node", TraceLoggingValue(peerId, "peerId"));
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
    root = RemoveRouteNode(root, ip, prefixLength, 0, &peerToRelease);
    ExReleaseSpinLockExclusive(&Lock, oldIrql);

    // Release the peer outside the lock if needed
    if (peerToRelease) {
        OvpnPeerCtxRelease(peerToRelease);
    }

    return STATUS_SUCCESS;
}

IPTrie::TrieNode*
IPTrie::RemoveRouteNode(TrieNode* node, const UCHAR* ip, int prefixLength, int depth, OvpnPeerContext** peerToRelease) {
    if (!node) return nullptr;

    if (depth < prefixLength) {
        int bit = (ip[depth / 8] >> (7 - (depth % 8))) & 1;
        node->children[bit] = RemoveRouteNode(node->children[bit], ip, prefixLength, depth + 1, peerToRelease);
    }
    else {
        if (node->peer) {
            *peerToRelease = node->peer;
            LOG_INFO("Peer node", TraceLoggingValue(node->peer->PeerId));
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
