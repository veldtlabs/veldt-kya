"""Gateway for the identity example: proof-of-possession required."""
from kya_gateway import Gateway, GatewayConfig

Gateway(GatewayConfig.from_yaml("gateway_identity.yaml")).run(
    host="127.0.0.1", port=8098)
