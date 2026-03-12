"""Pay with TON USDT using x402 client."""

import asyncio
import os

from tvm_core.signing import W5R1Signer, create_w5_sign_fn
from tvm_core.tonapi import TonapiProvider
from x402_tvm.exact.client import ExactTvmClientScheme


async def main():
    seed = bytes.fromhex(os.environ["WALLET_SEED"])
    signer = W5R1Signer(seed)
    sign_fn = create_w5_sign_fn(seed)

    provider = TonapiProvider(api_key=os.environ.get("TONAPI_KEY", ""))

    client = ExactTvmClientScheme(
        wallet_address=signer.address,
        public_key=signer.public_key,
        sign_fn=sign_fn,
        provider=provider,
        settler=provider,
    )

    payload = await client.create_payment_payload({
        "pay_to": "0:recipient_address_here",
        "asset": "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe",
        "amount": "1000000",
    })

    print("Payment payload created:")
    print(f"  From: {payload['from']}")
    print(f"  BoC length: {len(payload['settlementBoc'])}")


if __name__ == "__main__":
    asyncio.run(main())
