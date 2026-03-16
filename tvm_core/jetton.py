"""Jetton transfer payload construction (TEP-74)."""

from __future__ import annotations

import base64

from pytoniq_core import Address, Builder


def build_jetton_transfer_payload(
    destination: str,
    amount: int,
    response_destination: str | None = None,
    forward_ton_amount: int = 1,
    query_id: int = 0,
) -> str:
    """Build a TEP-74 jetton_transfer payload cell.

    Args:
        destination: Recipient address (raw format 0:hex).
        amount: Jetton amount in smallest units.
        response_destination: Where to send excess. Defaults to destination.
        forward_ton_amount: TON to forward with notification (default 1 nanoTON).
        query_id: Query ID (default 0).

    Returns:
        Base64-encoded BoC of the payload cell.
    """
    resp_dest = response_destination or destination

    b = Builder()
    b.store_uint(0x0F8A7EA5, 32)  # op: jetton_transfer
    b.store_uint(query_id, 64)
    b.store_coins(amount)
    b.store_address(Address(destination))
    b.store_address(Address(resp_dest))
    b.store_bit(0)  # no custom_payload
    b.store_coins(forward_ton_amount)
    b.store_bit(0)  # no forward_payload

    return base64.b64encode(b.end_cell().to_boc()).decode()
