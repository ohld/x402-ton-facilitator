"""W5R1 wallet signing for x402 TVM payments.

Creates signed external messages compatible with TONAPI gasless flow.
Port of the TS signing logic from x402-ton-poc/src/client.ts.
"""

from __future__ import annotations

import base64
from typing import Any, Callable, Coroutine

from nacl.signing import SigningKey
from pytoniq_core import Address, Builder, Cell

from .constants import EXTERNAL_SIGNED_OP, INTERNAL_SIGNED_OP, W5R1_CODE_HASH

# W5R1 wallet_id encoding: networkGlobalId with MSB cleared (v5r1 convention)
# Mainnet: (-239) & 0x7FFFFFFF = 0x7FFFFF11
# Testnet: (-3)   & 0x7FFFFFFF = 0x7FFFFFFD
W5R1_MAINNET_WALLET_ID = (-239) & 0x7FFFFFFF  # 2147483409
W5R1_TESTNET_WALLET_ID = (-3) & 0x7FFFFFFF  # 2147483645

# W5R1 contract code BOC (from @ton/ton WalletContractV5R1)
W5R1_CODE_BOC = (
    "te6cckECFAEAAoEAART/APSkE/S88sgLAQIBIAINAgFIAwQC3NAg10nBIJFbj2Mg1wsfIIIQ"
    "ZXh0br0hghBzaW50vbCSXwPgghBleHRuuo60gCDXIQHQdNch+kAw+kT4KPpEMFi9kVvg7UTQ"
    "gQFB1yH0BYMH9A5voTGRMOGAQNchcH/bPOAxINdJgQKAuZEw4HDiEA8CASAFDAIBIAYJAgFu"
    "BwgAGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8ACAUgKCwAXsyX7UTQcdch1wsfgABGy"
    "YvtRNDXCgCAAGb5fD2omhAgKDrkPoCwBAvIOAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fsh"
    "gwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIff"
    "ArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzY"
    "EAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCT"
    "INcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgk"
    "XCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jK"
    "AEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h"
    "8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vb"
    "MeHXTNC01sNe"
)

SEND_MSG_OP = 0x0EC3C86D
DEFAULT_SEND_MODE = 3  # PAY_GAS_SEPARATELY + IGNORE_ERRORS


def _load_w5r1_code() -> Cell:
    return Cell.one_from_boc(base64.b64decode(W5R1_CODE_BOC))


class W5R1Signer:
    """Signs W5R1 external messages for TON transfers."""

    def __init__(
        self,
        secret_key: bytes,
        workchain: int = 0,
        wallet_id: int = W5R1_MAINNET_WALLET_ID,
    ) -> None:
        if len(secret_key) != 32:
            raise ValueError(f"secret_key must be 32 bytes, got {len(secret_key)}")

        self._signing_key = SigningKey(secret_key)
        self._workchain = workchain
        self._wallet_id = wallet_id
        self._code_cell = _load_w5r1_code()
        self._state_init_cell = self._build_state_init()
        self._address_hash = self._state_init_cell.hash
        self._raw_address = f"{workchain}:{self._address_hash.hex()}"

    @property
    def address(self) -> str:
        return self._raw_address

    @property
    def public_key(self) -> str:
        return bytes(self._signing_key.verify_key).hex()

    def _build_state_init(self) -> Cell:
        pubkey = bytes(self._signing_key.verify_key)

        data_b = Builder()
        data_b.store_bit(1)  # is_signature_auth_allowed
        data_b.store_uint(0, 32)  # initial seqno
        data_b.store_int(self._wallet_id, 32)
        data_b.store_bytes(pubkey)  # 256-bit public key
        data_b.store_bit(0)  # no extensions dict
        data_cell = data_b.end_cell()

        # StateInit TL-B: split_depth(Maybe) special(Maybe) code(Maybe ^Cell)
        #                  data(Maybe ^Cell) library(HashmapE 256)
        si_b = Builder()
        si_b.store_bit(0)  # no split_depth
        si_b.store_bit(0)  # no special
        si_b.store_bit(1)  # has code
        si_b.store_ref(self._code_cell)
        si_b.store_bit(1)  # has data
        si_b.store_ref(data_cell)
        si_b.store_bit(0)  # no library
        return si_b.end_cell()

    def _build_internal_message(self, msg: dict[str, Any]) -> Cell:
        dest = Address(msg["address"])
        amount = int(msg["amount"])

        b = Builder()
        b.store_bit(0)  # int_msg_info$0
        b.store_bit(1)  # ihr_disabled
        b.store_bit(1)  # bounce
        b.store_bit(0)  # bounced
        b.store_uint(0, 2)  # src: addr_none$00
        b.store_address(dest)
        b.store_coins(amount)
        b.store_bit(0)  # no extra_currencies
        b.store_coins(0)  # ihr_fee
        b.store_coins(0)  # fwd_fee
        b.store_uint(0, 64)  # created_lt
        b.store_uint(0, 32)  # created_at

        # StateInit
        state_init_boc = msg.get("stateInit") or msg.get("state_init")
        if state_init_boc:
            si_cell = Cell.one_from_boc(base64.b64decode(state_init_boc))
            b.store_bit(1)  # has state_init
            b.store_bit(1)  # state_init as ref
            b.store_ref(si_cell)
        else:
            b.store_bit(0)  # no state_init

        # Body
        payload_boc = msg.get("payload")
        if payload_boc:
            body_cell = Cell.one_from_boc(base64.b64decode(payload_boc))
            b.store_bit(1)  # body as ref
            b.store_ref(body_cell)
        else:
            b.store_bit(0)  # empty inline body

        return b.end_cell()

    def _build_actions(
        self, messages: list[dict[str, Any]], send_mode: int
    ) -> Cell | None:
        if not messages:
            return None

        # Build from LAST message to FIRST (chained via refs)
        prev_action: Cell | None = None
        for msg in reversed(messages):
            int_msg = self._build_internal_message(msg)
            ab = Builder()
            ab.store_uint(SEND_MSG_OP, 32)
            ab.store_uint(send_mode, 8)
            ab.store_ref(int_msg)
            if prev_action is not None:
                ab.store_ref(prev_action)
            prev_action = ab.end_cell()

        return prev_action

    def sign_transfer(
        self,
        seqno: int,
        valid_until: int,
        messages: list[dict[str, Any]],
        send_mode: int = DEFAULT_SEND_MODE,
        auth_type: str = "external",
    ) -> str:
        """Sign a W5R1 transfer and return base64-encoded BoC.

        Args:
            seqno: Current wallet seqno.
            valid_until: Unix timestamp until the message is valid.
            messages: List of dicts with keys: address, amount, payload (optional b64 BoC),
                      stateInit (optional b64 BoC).
            send_mode: Send mode for all messages (default: 3).
            auth_type: "external" (default, for direct broadcast) or
                       "internal" (for gasless relay / self-relay settlement).

        Returns:
            Base64-encoded BoC of the signed external message.
        """
        actions = self._build_actions(messages, send_mode)

        # Build payload cell (the data that gets signed)
        payload_b = Builder()
        payload_b.store_int(self._wallet_id, 32)
        payload_b.store_uint(valid_until, 32)
        payload_b.store_uint(seqno, 32)
        payload_b.store_bit(0)  # not extension
        if actions is not None:
            payload_b.store_ref(actions)
        payload_cell = payload_b.end_cell()

        # Sign the payload cell hash
        signed = self._signing_key.sign(payload_cell.hash)
        signature = signed.signature

        # Build body cell — W5R1 requires opcode prefix for both formats
        body_b = Builder()
        if auth_type == "internal":
            body_b.store_uint(INTERNAL_SIGNED_OP, 32)  # 0x73696e74
        else:
            body_b.store_uint(EXTERNAL_SIGNED_OP, 32)  # 0x7369676e
        body_b.store_bytes(signature)
        body_b.store_int(self._wallet_id, 32)
        body_b.store_uint(valid_until, 32)
        body_b.store_uint(seqno, 32)
        body_b.store_bit(0)  # not extension
        if actions is not None:
            body_b.store_ref(actions)
        body_cell = body_b.end_cell()

        # Build external message
        ext_b = Builder()
        ext_b.store_uint(0b10, 2)  # ext_in_msg_info
        ext_b.store_uint(0b00, 2)  # src: addr_none
        ext_b.store_address(Address(self._raw_address))
        ext_b.store_coins(0)  # import_fee

        if seqno == 0:
            ext_b.store_bit(1)  # has state_init
            ext_b.store_bit(1)  # state_init as ref
            ext_b.store_ref(self._state_init_cell)
        else:
            ext_b.store_bit(0)  # no state_init

        ext_b.store_bit(1)  # body as ref
        ext_b.store_ref(body_cell)

        return base64.b64encode(ext_b.end_cell().to_boc()).decode()


def create_w5_sign_fn(
    secret_key: bytes,
    workchain: int = 0,
    wallet_id: int = W5R1_MAINNET_WALLET_ID,
) -> Callable[..., Coroutine[Any, Any, str]]:
    """Create an async sign_fn compatible with ExactTvmClientScheme.

    Args:
        secret_key: 32-byte Ed25519 seed.
        workchain: TON workchain (default 0).
        wallet_id: W5R1 wallet_id (mainnet -239, testnet -3).

    Returns:
        Async callable: (seqno, valid_until, messages) -> base64_boc
    """
    signer = W5R1Signer(secret_key, workchain, wallet_id)

    async def sign_fn(
        seqno: int, valid_until: int, messages: list[dict[str, Any]]
    ) -> str:
        return signer.sign_transfer(seqno, valid_until, messages)

    return sign_fn
