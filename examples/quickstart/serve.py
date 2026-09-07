"""Start the gateway with the example evaluators registered."""
import exfil_blocker  # noqa: F401  registers "exfil-blocker"
import payment_controls  # noqa: F401  registers "payment-controls"

from kya_gateway import Gateway, GatewayConfig

Gateway(GatewayConfig.from_yaml("gateway.yaml")).run(host="127.0.0.1", port=8099)
