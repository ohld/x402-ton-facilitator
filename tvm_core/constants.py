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

# W5 (Wallet v5r1) code hash — used to verify wallet contracts
# Base64-encoded hash of the W5R1 contract code
W5R1_CODE_HASH = "IINLe3KxEhR+Gy+0V7hOdNGjDwT3N9T2KmaOlVLSty8="

# Maximum BoC size in bytes (protection against DoS)
MAX_BOC_SIZE = 4096

# Payment scheme
SCHEME_EXACT = "exact"

# Settlement timeout (seconds)
SETTLEMENT_TIMEOUT = 15

# Default max relay commission in USDT nano units (0.5 USDT = 500000)
DEFAULT_MAX_RELAY_COMMISSION = 500_000

# TONAPI base URLs
TONAPI_MAINNET_URL = "https://tonapi.io"
TONAPI_TESTNET_URL = "https://testnet.tonapi.io"
