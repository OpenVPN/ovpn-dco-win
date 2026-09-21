"""Send a DATA_V2 packet that decrypts, from a source address of our choosing.

The other half of `ovpn-ioctl-test.exe --mode floatprobe`, which installs the key this
uses. Together they ask one question: will the driver move a peer's transport address to
the source address of an authenticated packet even when that address belongs to the
machine the driver is running on? If it will, a peer can park itself on the server's own
socket, and every control-channel write to it afterwards goes through the send path that
holds device->SpinLock (see tests/ioctl/README.md).

The packet layout is the driver's, from crypto.cpp:

    [ op/peer-id : 4 ][ packet id : 4 ][ auth tag : 16 ][ ciphertext ]

with the AEAD nonce being the packet id followed by the key's 8-byte nonce tail, and the
first 8 bytes doubling as additional authenticated data.

Needs scapy and cryptography, and Npcap on Windows: frames go out at layer 2, so the
sending machine's own stack never sees the forged source address.

    python float-probe.py --to 192.168.100.2 --port 11199 \
        --src-mac 00-15-5D-12-99-07 --dst-mac 00-15-5d-12-99-02 \
        --from 192.168.100.1:40000        # the address the peer was created with
    python float-probe.py ... --from 192.168.100.2:11199   # the driver's own address
"""
import argparse
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.all import Ether, IP, UDP, Raw, sendp, conf

# What --mode floatprobe installs. A probe, not a secret.
KEY = bytes([0x11]) * 32
NONCE_TAIL = bytes([0x22]) * 8
PEER_ID = 1
KEY_ID = 0

OVPN_OP_DATA_V2 = 9
OPCODE_SHIFT = 3


def build(packet_id, plaintext):
    header = struct.pack(">I", ((OVPN_OP_DATA_V2 << OPCODE_SHIFT | KEY_ID) << 24) | PEER_ID)
    pid = struct.pack(">I", packet_id)
    nonce = pid + NONCE_TAIL
    aad = header + pid
    sealed = AESGCM(KEY).encrypt(nonce, plaintext, aad)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return header + pid + tag + ciphertext


def parse_endpoint(text):
    host, _, port = text.rpartition(":")
    return host, int(port)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True, help="the driver's address")
    ap.add_argument("--port", type=int, default=11199)
    ap.add_argument("--from", dest="source", required=True, help="source address as ip:port")
    ap.add_argument("--src-mac", required=True)
    ap.add_argument("--dst-mac", required=True)
    ap.add_argument("--iface", default="Internal", help="substring of the interface name")
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--first-id", type=int, default=1)
    args = ap.parse_args()

    iface = next((i for i in conf.ifaces.values()
                  if args.iface in ((getattr(i, "name", "") or "") +
                                    (getattr(i, "description", "") or ""))), None)
    if iface is None:
        sys.exit("no interface matching %r" % args.iface)

    src_ip, src_port = parse_endpoint(args.source)
    # a plausible tunnelled packet; the driver floats before it looks at the payload
    plaintext = bytes.fromhex("450000140001000040007ce70a5800020a580001")

    pkts = []
    for n in range(args.count):
        payload = build(args.first_id + n, plaintext)
        pkts.append(Ether(src=args.src_mac.replace("-", ":"), dst=args.dst_mac.replace("-", ":"))
                    / IP(src=src_ip, dst=args.to)
                    / UDP(sport=src_port, dport=args.port)
                    / Raw(payload))

    sendp(pkts, iface=iface, verbose=False)
    print("sent %d packet(s) from %s:%d to %s:%d via %s"
          % (args.count, src_ip, src_port, args.to, args.port, getattr(iface, "name", iface)))


if __name__ == "__main__":
    main()
