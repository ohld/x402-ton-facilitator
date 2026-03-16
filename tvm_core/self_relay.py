"""Self-relay: facilitator sponsors gas and relays user's signed W5 messages.

Architecture:
  1. Client calls /prepare → facilitator returns seqno, messages to sign
  2. Client signs with authType='internal' (W5 internal_signed format)
  3. Client sends signed BoC to facilitator
  4. Facilitator wraps the signed body in an internal message from its own wallet
  5. Facilitator sends the internal message with TON for gas → user's W5 executes

This eliminates the need for a third-party gasless relay (e.g., TONAPI gasless).
The facilitator IS the relay.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

from pytoniq_core import Address, Builder, Cell

from .address import normalize_address
from .boc import parse_external_message
from .constants import (
    DEFAULT_GAS_AMOUNT,
    DEFAULT_JETTON_FWD_AMOUNT,
    USDT_MASTER,
)
from .jetton import build_jetton_transfer_payload
from .providers import TonProvider
from .signing import W5R1Signer

logger = logging.getLogger(__name__)


class SelfRelay:
    """Self-relay facilitator that sponsors gas for W5 wallet users.

    Holds a funded wallet (W5R1) and sends internal messages to user wallets,
    attaching TON for gas. Equivalent to what TONAPI gasless does, but
    self-hosted inside the facilitator.
    """

    def __init__(
        self,
        provider: TonProvider,
        private_key_hex: str,
        gas_amount: int = DEFAULT_GAS_AMOUNT,
        wallet_id: int = -239,
    ) -> None:
        self._provider = provider
        self._gas_amount = gas_amount
        self._signer = W5R1Signer(
            bytes.fromhex(private_key_hex),
            wallet_id=wallet_id,
        )

    @property
    def address(self) -> str:
        return self._signer.address

    @property
    def public_key(self) -> str:
        return self._signer.public_key

    async def get_balance(self) -> int:
        """Get facilitator wallet balance in nanoTON."""
        state = await self._provider.get_account_state(self._signer.address)
        return state.get("balance", 0)

    async def prepare(
        self,
        wallet_address: str,
        pay_to: str,
        token_master: str,
        amount: str,
    ) -> dict[str, Any]:
        """Prepare signing data for a client.

        Queries the client's seqno, resolves their jetton wallet,
        and constructs the jetton transfer message for signing.

        Args:
            wallet_address: Client's W5 wallet address (any format).
            pay_to: Merchant's address (any format).
            token_master: Jetton master address (raw format).
            amount: Payment amount in jetton's smallest units.

        Returns:
            Dict with seqno, validUntil, walletId, and messages array.
        """
        wallet_raw = normalize_address(wallet_address)
        pay_to_raw = normalize_address(pay_to)

        # Get client's current seqno
        seqno = await self._provider.get_seqno(wallet_raw)

        # Resolve client's jetton wallet for the payment token
        jetton_wallet = await self._provider.get_jetton_wallet(
            token_master, wallet_raw
        )
        jetton_wallet = normalize_address(jetton_wallet)

        # Build jetton transfer payload
        payload_boc = build_jetton_transfer_payload(
            destination=pay_to_raw,
            amount=int(amount),
            response_destination=wallet_raw,  # excess back to sender
        )

        valid_until = int(time.time()) + 300  # 5 min validity

        return {
            "seqno": seqno,
            "validUntil": valid_until,
            "walletId": -239,  # mainnet W5R1 default
            "messages": [
                {
                    "address": jetton_wallet,
                    "amount": str(DEFAULT_JETTON_FWD_AMOUNT),
                    "payload": payload_boc,
                }
            ],
        }

    async def relay(
        self,
        signed_external_boc: str,
        user_wallet_address: str,
    ) -> str:
        """Relay a user's signed W5 message by sponsoring gas.

        Extracts the internal_signed body from the client's external message,
        wraps it in an internal message from the facilitator's wallet,
        and broadcasts it.

        Args:
            signed_external_boc: Base64-encoded BoC of the client's signed
                external message (contains internal_signed body).
            user_wallet_address: Client's W5 wallet address (raw format).

        Returns:
            BoC hash of the submitted message (for tracking).

        Raises:
            ValueError: If the BoC is malformed.
            RuntimeError: If broadcast fails.
        """
        # Extract the body cell from the external message wrapper
        body_cell = parse_external_message(signed_external_boc)
        body_boc = base64.b64encode(body_cell.to_boc()).decode()

        user_raw = normalize_address(user_wallet_address)

        # Build the internal message from facilitator to user's W5 wallet
        # The body is the user's internal_signed request
        relay_msg = {
            "address": user_raw,
            "amount": str(self._gas_amount),
            "payload": body_boc,
        }

        # Get facilitator's seqno
        fac_seqno = await self._provider.get_seqno(self._signer.address)
        fac_valid_until = int(time.time()) + 120  # 2 min for facilitator tx

        # Sign and build the facilitator's external message
        fac_boc = self._signer.sign_transfer(
            seqno=fac_seqno,
            valid_until=fac_valid_until,
            messages=[relay_msg],
            auth_type="external",  # facilitator sends normal external message
        )

        # Broadcast
        ok = await self._provider.send_boc(fac_boc)
        if not ok:
            raise RuntimeError("Failed to broadcast relay message")

        logger.info(
            "Relayed payment: user=%s fac_seqno=%d gas=%d",
            user_raw[:20],
            fac_seqno,
            self._gas_amount,
        )

        return fac_boc[:16]  # return a tracking ID
