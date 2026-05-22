#!/usr/bin/env python3
"""Decode raw BGP messages using ExaBGP's decoder"""

from exabgp.bgp.message import Update, Open, Notification
from exabgp.bgp.message.direction import Direction
from exabgp.bgp.message.open.capability import Capabilities, Capability, Negotiated
from exabgp.bgp.message.open import Version, ASN, RouterID, HoldTime


class BGPDecoder:
    """Decode raw BGP messages from bytes"""

    MARKER = b'\xff' * 16

    def __init__(self, local_asn: int = 65533, peer_asn: int = 65534,
                 local_router_id: str = "10.0.0.1", peer_router_id: str = "10.0.0.2",
                 families: list = None):
        """
        Initialize BGP decoder with capability negotiation context.

        Args:
            local_asn: Local AS number
            peer_asn: Peer AS number
            local_router_id: Local router ID
            peer_router_id: Peer router ID
            families: List of (afi, safi) tuples, e.g. [(1, 1)] for IPv4 unicast
        """
        if families is None:
            families = [(1, 1)]  # IPv4 unicast default

        self.families = families
        self.local_asn = local_asn
        self.peer_asn = peer_asn

        self._negotiated = self._build_negotiated(
            local_asn, peer_asn, local_router_id, peer_router_id, families
        )

    def _build_negotiated(self, local_asn, peer_asn, local_rid, peer_rid, families):
        """Build negotiated capabilities context"""
        capa = Capabilities()
        capa[Capability.CODE.MULTIPROTOCOL] = families

        local_open = Open(
            Version(4), ASN(local_asn), HoldTime(180),
            RouterID(local_rid), capa
        )
        peer_open = Open(
            Version(4), ASN(peer_asn), HoldTime(180),
            RouterID(peer_rid), capa
        )

        negotiated = Negotiated(None)
        negotiated.sent(local_open)
        negotiated.received(peer_open)
        return negotiated

    def _strip_header(self, raw: bytes) -> tuple:
        """
        Strip BGP header and return (msg_type, payload).

        Returns:
            Tuple of (message_type, payload_bytes)
        """
        if raw.startswith(self.MARKER):
            msg_type = raw[18]
            msg_len = (raw[16] << 8) + raw[17]
            payload = raw[19:msg_len]
            return msg_type, payload
        return 2, raw  # Assume UPDATE if no header

    def decode_update(self, raw: bytes) -> Update:
        """
        Decode a BGP UPDATE message.

        Args:
            raw: Raw BGP message bytes (with or without header)

        Returns:
            Decoded Update object
        """
        msg_type, payload = self._strip_header(raw)

        if msg_type != 2:
            raise ValueError(f"Expected UPDATE (type 2), got type {msg_type}")

        return Update.unpack_message(payload, Direction.IN, self._negotiated)

    def decode_open(self, raw: bytes) -> Open:
        """
        Decode a BGP OPEN message.

        Args:
            raw: Raw BGP message bytes (with or without header)

        Returns:
            Decoded Open object
        """
        msg_type, payload = self._strip_header(raw)

        if msg_type != 1:
            raise ValueError(f"Expected OPEN (type 1), got type {msg_type}")

        return Open.unpack_message(payload, Direction.IN, self._negotiated)

    def decode_notification(self, raw: bytes) -> Notification:
        """
        Decode a BGP NOTIFICATION message.

        Args:
            raw: Raw BGP message bytes (with or without header)

        Returns:
            Decoded Notification object
        """
        msg_type, payload = self._strip_header(raw)

        if msg_type != 3:
            raise ValueError(f"Expected NOTIFICATION (type 3), got type {msg_type}")

        return Notification.unpack_message(payload, Direction.IN, self._negotiated)

    def decode(self, raw: bytes):
        """
        Auto-detect and decode any BGP message type.

        Args:
            raw: Raw BGP message bytes

        Returns:
            Decoded message object (Update, Open, or Notification)
        """
        if not raw.startswith(self.MARKER):
            # No header, assume UPDATE
            return self.decode_update(raw)

        msg_type = raw[18]

        if msg_type == 1:
            return self.decode_open(raw)
        elif msg_type == 2:
            return self.decode_update(raw)
        elif msg_type == 3:
            return self.decode_notification(raw)
        elif msg_type == 4:
            return None  # KEEPALIVE - no payload to decode
        else:
            raise ValueError(f"Unknown BGP message type: {msg_type}")


def decode_bgp_message(raw: bytes, families: list = None):
    """
    Convenience function to decode a single BGP message.

    Args:
        raw: Raw BGP message bytes
        families: List of (afi, safi) tuples

    Returns:
        Decoded message object
    """
    decoder = BGPDecoder(families=families)
    return decoder.decode(raw)


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: decoder.py <hex-message> [afi safi]")
        print("Example: decoder.py FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF001E0200000007900F0003000101 1 1")
        sys.exit(1)

    hex_msg = sys.argv[1].replace(":", "").replace(" ", "")
    raw = bytes.fromhex(hex_msg)

    families = None
    if len(sys.argv) >= 4:
        afi = int(sys.argv[2])
        safi = int(sys.argv[3])
        families = [(afi, safi)]

    decoder = BGPDecoder(families=families)

    try:
        msg = decoder.decode(raw)

        if msg is None:
            print("KEEPALIVE")
        elif isinstance(msg, Update):
            for nlri in msg.nlris:
                print(f"NLRI: {nlri}")
            print(f"Attributes: {msg.attributes}")
        elif isinstance(msg, Open):
            print(f"OPEN: {msg}")
        elif isinstance(msg, Notification):
            print(f"NOTIFICATION: {msg}")
    except Exception as e:
        print(f"Decode error: {e}")
        sys.exit(1)
