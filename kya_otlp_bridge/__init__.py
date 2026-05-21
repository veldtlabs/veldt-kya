"""
KYA OTLP Bridge — translates OpenTelemetry spans to KYA HTTP events.

Why: frameworks like OpenCLAW emit OTLP traces natively. Without this
bridge, KYA would need first-party adapters in every emitting language.
With it, ANY OTel-instrumented agent runtime can feed KYA by setting
`OTEL_EXPORTER_OTLP_ENDPOINT` to point here.

Architecture
------------
                                                  (HTTP POST)
  framework emits OTel  ->  OTLP/HTTP receiver  ----------->  KYA /events/rogue
   (OpenCLAW, OpenLLMetry-instrumented agent)    (this svc)   KYA /events/invocation

The bridge is configurable via SpanMapper rules — see mapper.py.

Public API
----------
    KyaOtlpBridge.create_app(mapper, client) -> FastAPI app
    SpanMapper                                 -> per-attribute rules

Module-level entrypoint:
    from kya_otlp_bridge import KyaOtlpBridge, SpanMapper
"""

# Lazy attribute loading (PEP 562) so `import kya_otlp_bridge` works
# even when fastapi isn't installed — the bridge entrypoint is only
# accessed when someone actively runs the OTel sidecar.
from .mapper import MapResult, SpanMapper

__all__ = ["KyaOtlpBridge", "SpanMapper", "MapResult"]
__version__ = "0.1.0"


def __getattr__(name):
    if name == "KyaOtlpBridge":
        from .bridge import KyaOtlpBridge as _K
        return _K
    raise AttributeError(f"module 'kya_otlp_bridge' has no attribute {name!r}")
