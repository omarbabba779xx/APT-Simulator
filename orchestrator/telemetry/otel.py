"""Optional OpenTelemetry log exporter.

Each audit event becomes an OTel LogRecord with attributes mirroring the
event payload. Sends via OTLP to the configured endpoint.

Activated only when:
  - opentelemetry-sdk + opentelemetry-exporter-otlp are installed, AND
  - APT_SIM_OTEL=1 in the environment

Endpoint comes from the standard OTEL_EXPORTER_OTLP_ENDPOINT env var.
"""
from __future__ import annotations

import os
from typing import Any


class OtelExporter:
    """Adapter exposing a `publish(entry)` callable; no-op on import failure."""

    def __init__(self, service_name: str = "apt-simulator-orchestrator") -> None:
        self.enabled = False
        self._logger = None
        try:
            from opentelemetry import _logs as logs_api  # type: ignore[import-not-found]
            from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (  # type: ignore[import-not-found]
                OTLPLogExporter,
            )
            from opentelemetry.sdk._logs import LoggerProvider  # type: ignore[import-not-found]
            from opentelemetry.sdk._logs.export import (  # type: ignore[import-not-found]
                BatchLogRecordProcessor,
            )
            from opentelemetry.sdk.resources import Resource  # type: ignore[import-not-found]
        except ImportError:
            return

        try:
            provider = LoggerProvider(resource=Resource.create({"service.name": service_name}))
            provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
            logs_api.set_logger_provider(provider)
            self._logger = logs_api.get_logger("apt_simulator.audit")
            self.enabled = True
        except Exception:  # broad: any OTel init failure → silent disable
            self.enabled = False

    def publish(self, entry: dict[str, Any]) -> None:
        if not self.enabled or self._logger is None:
            return
        try:
            from opentelemetry._logs import LogRecord, SeverityNumber  # type: ignore[import-not-found]
            attrs = {
                "audit.event": entry.get("event", ""),
                "audit.hash": entry.get("hash", ""),
                "audit.prev": entry.get("prev", ""),
            }
            payload = entry.get("payload") or {}
            for k, v in payload.items():
                if isinstance(v, (str, int, float, bool)):
                    attrs[f"payload.{k}"] = v
            record = LogRecord(
                timestamp=int(float(entry.get("ts", 0)) * 1e9),
                severity_number=SeverityNumber.INFO,
                severity_text="INFO",
                body=entry.get("event", ""),
                attributes=attrs,
            )
            self._logger.emit(record)
        except Exception:
            pass


def maybe_install(audit, service_name: str = "apt-simulator-orchestrator") -> bool:
    """Install OTel exporter onto an AuditLog if env opt-in is set. Returns True if active."""
    if os.environ.get("APT_SIM_OTEL") != "1":
        return False
    exporter = OtelExporter(service_name=service_name)
    if not exporter.enabled:
        return False
    audit.add_publisher(exporter.publish)
    return True
