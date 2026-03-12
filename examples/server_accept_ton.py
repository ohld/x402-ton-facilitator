"""Accept TON USDT payments on a FastAPI server using x402."""

from fastapi import FastAPI, Request, Response

from tvm_core.tonapi import TonapiProvider
from tvm_core.types import TvmPaymentPayload
from tvm_core.verify import VerifyConfig, verify_payment

app = FastAPI()

TONAPI_KEY = "your-tonapi-key"
PAY_TO = "0:your_wallet_address_hex"
USDT_MASTER = "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"

provider = TonapiProvider(api_key=TONAPI_KEY)
config = VerifyConfig()


@app.get("/premium-content")
async def premium_content(request: Request):
    x402 = request.headers.get("X-PAYMENT")
    if not x402:
        return Response(status_code=402, headers={
            "X-PAYMENT-REQUIRED": "true",
            "X-PAYMENT-AMOUNT": "1000000",
            "X-PAYMENT-ASSET": USDT_MASTER,
            "X-PAYMENT-PAY-TO": PAY_TO,
            "X-PAYMENT-NETWORK": "tvm:-239",
            "X-PAYMENT-SCHEME": "exact",
        })

    payload = TvmPaymentPayload.model_validate_json(x402)
    result = await verify_payment(
        payload, scheme="exact", network="tvm:-239",
        required_amount="1000000", required_pay_to=PAY_TO,
        required_asset=USDT_MASTER, provider=provider, config=config,
    )
    if not result.ok:
        return Response(status_code=402, content=result.reason)

    return {"content": "You have access!"}
