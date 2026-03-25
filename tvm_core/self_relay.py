"""Self-relay: facilitator sponsors gas and relays user's signed W5 messages.

Architecture:
  1. Client signs with authType='internal' (W5 internal_signed format)
  2. Client wraps signed body in an internal message BoC (dest=user wallet)
  3. Facilitator parses the internal message BoC, extracts body + stateInit
  4. Facilitator wraps the signed body in a new internal message with gas
  5. Facilitator sends via its own W5 wallet -> user's W5 executes
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

from pytoniq_core import Address, Builder, Cell

from .address import normalize_address
from .boc import parse_settlement_boc
from .constants import (
    DEFAULT_GAS_AMOUNT,
    DEFAULT_JETTON_FWD_AMOUNT,
    USDT_MASTER,
)
from .jetton import build_jetton_transfer_payload
from .providers import TonProvider
from .signing import W5R1Signer, W5R1_MAINNET_WALLET_ID

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
        wallet_id: int = W5R1_MAINNET_WALLET_ID,
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
        """Prepare signing data for a client."""
        wallet_raw = normalize_address(wallet_address)
        pay_to_raw = normalize_address(pay_to)

        seqno = await self._provider.get_seqno(wallet_raw)

        jetton_wallet = await self._provider.get_jetton_wallet(
            token_master, wallet_raw
        )
        jetton_wallet = normalize_address(jetton_wallet)

        payload_boc = build_jetton_transfer_payload(
            destination=pay_to_raw,
            amount=int(amount),
            response_destination=wallet_raw,
        )

        valid_until = int(time.time()) + 300

        return {
            "seqno": seqno,
            "validUntil": valid_until,
            "walletId": W5R1_MAINNET_WALLET_ID,
            "messages": [
                {
                    "address": jetton_wallet,
                    "amount": str(DEFAULT_JETTON_FWD_AMOUNT),
                    "payload": payload_boc,
                }
            ],
        }

    def _build_relay_boc(
        self,
        body_boc: str,
        user_raw: str,
        fac_seqno: int,
        gas_amount: int,
        state_init_boc: str | None = None,
    ) -> str:
        """Build the facilitator's relay external message.

        Wraps the user's signed W5 body in an internal message from
        the facilitator's wallet, attaching TON for gas.
        """
        relay_msg: dict[str, Any] = {
            "address": user_raw,
            "amount": str(gas_amount),
            "payload": body_boc,
        }
        if state_init_boc:
            relay_msg["state_init"] = state_init_boc

        fac_valid_until = int(time.time()) + 120
        return self._signer.sign_transfer(
            seqno=fac_seqno,
            valid_until=fac_valid_until,
            messages=[relay_msg],
            auth_type="external",
        )

    async def _estimate_gas(
        self,
        body_boc: str,
        user_raw: str,
        fac_seqno: int,
        state_init_boc: str | None = None,
    ) -> int | None:
        """Estimate gas by emulating the relay tx. Returns nanoTON or None."""
        trial_boc = self._build_relay_boc(
            body_boc, user_raw, fac_seqno, self._gas_amount, state_init_boc
        )

        emulation = await self._provider.emulate(trial_boc)
        if emulation is None:
            return None

        total_fees = 0
        def walk(node: dict) -> None:
            nonlocal total_fees
            tx = node.get("transaction", {})
            total_fees += tx.get("total_fees", 0)
            for child in node.get("children", []):
                walk(child)

        walk(emulation.get("trace", {}))

        if total_fees <= 0:
            return None

        return total_fees

    async def relay(
        self,
        settlement_boc: str,
    ) -> str:
        """Relay a user's signed message (gasless mode).

        Parses the internal message BoC, extracts body + stateInit,
        wraps in a new internal message with gas from facilitator's wallet.
        """
        settlement = parse_settlement_boc(settlement_boc)
        user_raw = normalize_address(settlement.sender_address)

        body_boc = base64.b64encode(settlement.body_cell.to_boc()).decode()

        # Encode stateInit if present (for wallet deployment)
        state_init_boc = None
        if settlement.state_init_cell is not None:
            state_init_boc = base64.b64encode(
                settlement.state_init_cell.to_boc()
            ).decode()

        fac_seqno = await self._provider.get_seqno(self._signer.address)

        # Emulation-based gas estimation
        estimated_gas = await self._estimate_gas(
            body_boc, user_raw, fac_seqno, state_init_boc
        )
        gas_amount = estimated_gas if estimated_gas else self._gas_amount

        logger.info(
            "Gasless relay: gas=%d nanoTON (%s)",
            gas_amount,
            "emulated" if estimated_gas else "default",
        )

        fac_boc = self._build_relay_boc(
            body_boc, user_raw, fac_seqno, gas_amount, state_init_boc
        )

        ok = await self._provider.send_boc(fac_boc)
        if not ok:
            raise RuntimeError("Failed to broadcast relay message")

        return fac_boc[:16]
