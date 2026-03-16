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
    INTERNAL_SIGNED_OP,
    EXTERNAL_SIGNED_OP,
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
    ) -> str:
        """Build the facilitator's relay external message."""
        relay_msg = {
            "address": user_raw,
            "amount": str(gas_amount),
            "payload": body_boc,
        }
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
    ) -> int | None:
        """Estimate gas by emulating the relay tx. Returns nanoTON or None."""
        # Build with default gas for emulation
        trial_boc = self._build_relay_boc(body_boc, user_raw, fac_seqno, self._gas_amount)

        emulation = await self._provider.emulate(trial_boc)
        if emulation is None:
            return None

        # Sum all fees across the trace
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

        # Add 50% buffer for safety (gas prices can fluctuate between emulation and broadcast)
        return int(total_fees * 1.5)

    @staticmethod
    def _detect_opcode(body_cell: Cell) -> int | None:
        """Detect the auth opcode from the body cell."""
        cs = body_cell.begin_parse()
        if cs.remaining_bits >= 32:
            return cs.preload_uint(32)
        return None

    async def relay(
        self,
        signed_external_boc: str,
        user_wallet_address: str,
    ) -> str:
        """Relay a user's signed message.

        Dual-mode settlement:
        - internal_signed (0x73696e74): gasless — facilitator wraps + sponsors gas
        - external_signed (0x7369676e): direct — facilitator broadcasts user's BoC as-is

        Uses TONAPI emulation for precise gas estimation in gasless mode.
        """
        body_cell = parse_external_message(signed_external_boc)
        opcode = self._detect_opcode(body_cell)

        # --- Non-gasless: user signed external, pays own gas ---
        if opcode == EXTERNAL_SIGNED_OP:
            logger.info("Direct broadcast (user pays gas): %s...", user_wallet_address[:20])
            ok = await self._provider.send_boc(signed_external_boc)
            if not ok:
                raise RuntimeError("Failed to broadcast user's external message")
            return signed_external_boc[:16]

        # --- Gasless: facilitator wraps in internal message + sponsors gas ---
        body_boc = base64.b64encode(body_cell.to_boc()).decode()
        user_raw = normalize_address(user_wallet_address)
        fac_seqno = await self._provider.get_seqno(self._signer.address)

        # Emulation-based gas estimation
        estimated_gas = await self._estimate_gas(body_boc, user_raw, fac_seqno)
        gas_amount = estimated_gas if estimated_gas else self._gas_amount

        logger.info(
            "Gasless relay: gas=%d nanoTON (%s)",
            gas_amount,
            "emulated" if estimated_gas else "default",
        )

        fac_boc = self._build_relay_boc(body_boc, user_raw, fac_seqno, gas_amount)

        ok = await self._provider.send_boc(fac_boc)
        if not ok:
            raise RuntimeError("Failed to broadcast relay message")

        return fac_boc[:16]
