#!/usr/bin/env python3
"""Create a W5R1 wallet on TON testnet and print its address.

Usage:
    python scripts/setup_testnet.py [--seed HEX_SEED]

If no seed is given, a random one is generated.
Fund the printed address via https://t.me/testgiver_ton_bot
"""

import argparse
import secrets

from tvm_core.address import raw_to_friendly
from tvm_core.signing import W5R1Signer


def main():
    parser = argparse.ArgumentParser(description="Create a W5R1 testnet wallet")
    parser.add_argument("--seed", help="32-byte hex seed (64 hex chars)")
    args = parser.parse_args()

    if args.seed:
        seed = bytes.fromhex(args.seed)
    else:
        seed = secrets.token_bytes(32)

    signer = W5R1Signer(seed, wallet_id=-3)  # -3 = testnet

    print(f"Seed (hex):       {seed.hex()}")
    print(f"Public key (hex): {signer.public_key}")
    print(f"Raw address:      {signer.address}")
    print(f"Friendly (test):  {raw_to_friendly(signer.address, testnet=True)}")
    print()
    print("Fund this address at https://t.me/testgiver_ton_bot")
    print("Then set env vars:")
    print(f'  export TEST_WALLET_SEED="{seed.hex()}"')
    print(f'  export TESTNET=true')


if __name__ == "__main__":
    main()
