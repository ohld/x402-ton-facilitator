"""TON blockchain constants for x402 payment verification."""

# CAIP-2 network identifiers for TVM chains
# TON mainnet (workchain 0, global_id -239)
TVM_MAINNET = "tvm:-239"
# TON testnet (workchain 0, global_id -3)
TVM_TESTNET = "tvm:-3"

SUPPORTED_NETWORKS = {TVM_MAINNET, TVM_TESTNET}

# USDT Jetton Master contract address on TON (same on mainnet and testnet for now)
USDT_MASTER = "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"

# Jetton transfer opcode (TEP-74)
JETTON_TRANSFER_OP = 0x0F8A7EA5

# W5 message opcodes
INTERNAL_SIGNED_OP = 0x73696E74  # "sint" — W5 internal_signed
EXTERNAL_SIGNED_OP = 0x7369676E  # "sign" — W5 external_signed

# W5 (Wallet v5r1) code hash — used to verify wallet contracts
# Base64-encoded hash of the W5R1 contract code
W5R1_CODE_HASH = "IINLe3KxEhR+Gy+0V7hOdNGjDwT3N9T2KmaOlVLSty8="

# Maximum BoC size in bytes (protection against DoS)
MAX_BOC_SIZE = 4096

# Payment scheme
SCHEME_EXACT = "exact"

# Settlement timeout (seconds)
SETTLEMENT_TIMEOUT = 15

# Default gas amount in nanoTON for self-relay.
# This covers: user wallet compute (~0.003 TON) + jetton fwd amount (below).
# TONAPI gasless relay uses ~0.054 TON. We use 0.06 TON with buffer.
# Real cost per payment: ~0.009 TON; excess stays in user's wallet.
DEFAULT_GAS_AMOUNT = 60_000_000  # 0.06 TON

# Default TON amount to attach to jetton transfer messages.
# Covers: jetton_internal_transfer + notification + excess return (~0.002 TON actual).
# Must be enough for the full jetton chain; excess returns to sender.
DEFAULT_JETTON_FWD_AMOUNT = 10_000_000  # 0.01 TON

# TONAPI base URLs
TONAPI_MAINNET_URL = "https://tonapi.io"
TONAPI_TESTNET_URL = "https://testnet.tonapi.io"
