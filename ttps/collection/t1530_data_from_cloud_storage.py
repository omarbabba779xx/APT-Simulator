"""T1530 - Data from Cloud Storage Object (simulation only).

Simulation: writes synthetic cloud audit events for listing and reading storage
objects. No cloud SDK is imported and no provider endpoint is contacted.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..base import TTP, TTPResult, registry

_MARKER_NAME = "t1530_cloud_storage_access.jsonl"
_PROVIDERS = {"aws", "azure", "gcp"}


def _object_names(params: dict[str, Any]) -> list[str]:
    supplied = params.get("objects")
    if supplied:
        return [str(name) for name in list(supplied)[:100]]
    count = max(1, min(int(params.get("object_count", 5)), 100))
    return [f"finance/export_{idx:03d}.csv" for idx in range(1, count + 1)]


def _aws_events(bucket: str, objects: list[str], source_ip: str, ts: float) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBucket",
            "requestParameters.bucketName": bucket,
            "sourceIPAddress": source_ip,
            "userAgent": "AptSim/1.0 cloud-storage-sim",
            "eventTime": ts,
            "_sim": "APT_SIM_COLLECTION_T1530",
        }
    ]
    for idx, name in enumerate(objects, start=1):
        events.append(
            {
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "requestParameters.bucketName": bucket,
                "requestParameters.key": name,
                "sourceIPAddress": source_ip,
                "userAgent": "AptSim/1.0 cloud-storage-sim",
                "eventTime": ts + idx,
                "_sim": "APT_SIM_COLLECTION_T1530",
            }
        )
    return events


def _azure_events(container: str, objects: list[str], source_ip: str, ts: float) -> list[dict[str, Any]]:
    return [
        {
            "operationName": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "container": container,
            "objectKey": name,
            "callerIpAddress": source_ip,
            "eventTime": ts + idx,
            "_sim": "APT_SIM_COLLECTION_T1530",
        }
        for idx, name in enumerate(objects)
    ]


def _gcp_events(bucket: str, objects: list[str], source_ip: str, ts: float) -> list[dict[str, Any]]:
    return [
        {
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.objects.get",
            "bucket": bucket,
            "object": name,
            "requestMetadata.callerIp": source_ip,
            "eventTime": ts + idx,
            "_sim": "APT_SIM_COLLECTION_T1530",
        }
        for idx, name in enumerate(objects)
    ]


class T1530DataFromCloudStorage(TTP):
    attack_id = "T1530"
    name = "Data from Cloud Storage Object (sim)"
    description = "Generate cloud audit markers for storage object listing and access, without cloud API calls"
    tactic = "collection"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        provider = str(params.get("provider", "aws")).lower()
        if provider not in _PROVIDERS:
            return TTPResult(
                ok=False,
                error=f"unsupported provider '{provider}', expected aws|azure|gcp",
                started_at=started,
                finished_at=time.time(),
            )

        bucket = str(params.get("bucket", "apt-sim-lab-bucket"))
        source_ip = str(params.get("source_ip", "198.51.100.24"))
        objects = _object_names(params)
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_path = marker_dir / _MARKER_NAME
        ts = time.time()

        if provider == "aws":
            events = _aws_events(bucket, objects, source_ip, ts)
        elif provider == "azure":
            events = _azure_events(bucket, objects, source_ip, ts)
        else:
            events = _gcp_events(bucket, objects, source_ip, ts)

        marker_path.write_text(
            "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
            encoding="utf-8",
        )

        return TTPResult(
            ok=True,
            output=f"wrote {len(events)} synthetic {provider} storage access event(s) to {marker_path}",
            artifacts=[str(marker_path)],
            started_at=started,
            finished_at=time.time(),
            extra={
                "provider": provider,
                "bucket": bucket,
                "source_ip": source_ip,
                "object_count": len(objects),
                "event_count": len(events),
                "objects": objects[:20],
                "marker": str(marker_path),
            },
        )

    def cleanup(self, params: dict[str, Any]) -> TTPResult:
        marker_dir = Path(params.get("marker_dir", "data/sim_markers"))
        marker_path = marker_dir / _MARKER_NAME
        if marker_path.exists():
            marker_path.unlink()
        return TTPResult(ok=True, output="cloud storage marker removed", started_at=time.time(), finished_at=time.time())

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Cloud Storage Object Access Burst (APT Simulator T1530)",
            "id": "b1530000-0000-0000-0000-000000001530",
            "status": "experimental",
            "description": (
                "Detects cloud storage listing or object reads that can indicate "
                "collection from S3, Azure Blob Storage, or GCS."
            ),
            "references": ["https://attack.mitre.org/techniques/T1530/"],
            "tags": ["attack.collection", "attack.t1530"],
            "logsource": {"product": "cloud"},
            "detection": {
                "selection_aws": {
                    "eventSource": "s3.amazonaws.com",
                    "eventName": ["ListBucket", "GetObject"],
                },
                "selection_azure": {
                    "operationName|contains": "storageAccounts/blobServices/containers/blobs/read",
                },
                "selection_gcp": {
                    "serviceName": "storage.googleapis.com",
                    "methodName|contains": "storage.objects.",
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["Backup jobs", "Data lake ETL jobs", "Cloud inventory scanners"],
            "level": "medium",
        }

    def synthetic_events(self, params: dict[str, Any], result: Any = None) -> list[dict[str, Any]]:
        provider = str(params.get("provider", "aws")).lower()
        bucket = str(params.get("bucket", "apt-sim-lab-bucket"))
        source_ip = str(params.get("source_ip", "198.51.100.24"))
        objects = _object_names(params)
        ts = time.time()
        if provider == "aws":
            return _aws_events(bucket, objects[:1], source_ip, ts)
        if provider == "azure":
            return _azure_events(bucket, objects[:1], source_ip, ts)
        if provider == "gcp":
            return _gcp_events(bucket, objects[:1], source_ip, ts)
        return []


registry.register(T1530DataFromCloudStorage())
