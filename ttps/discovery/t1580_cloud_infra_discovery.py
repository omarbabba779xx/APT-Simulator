"""T1580 — Cloud Infrastructure Discovery (multi-provider, read-only).

Supported providers (selected via params['provider']):

  - aws    (default): EC2 DescribeInstances + S3 ListBuckets via boto3
  - azure : ResourceGraph or ResourceManagementClient via azure-identity + azure-mgmt-resource

All API calls are strictly Describe* / List* / read-only. Refuses to run if the
target provider's SDK is not installed or no credentials are present.

Will contact the cloud provider — use only with credentials scoped to a lab
account.
"""
from __future__ import annotations

import time
from typing import Any

from ..base import TTP, TTPResult, registry


def _run_aws(params: dict[str, Any], started: float) -> TTPResult:
    try:
        import boto3  # type: ignore[import-not-found,import-untyped]
        from botocore.exceptions import (  # type: ignore[import-not-found,import-untyped]
            BotoCoreError,
            ClientError,
            NoCredentialsError,
        )
    except ImportError:
        return TTPResult(
            ok=False,
            error="boto3 not installed; install via: pip install -e \".[aws]\"",
            started_at=started,
            finished_at=time.time(),
        )

    region = str(params.get("region", "us-east-1"))
    extra: dict[str, Any] = {"provider": "aws", "region": region}
    try:
        session = boto3.Session(region_name=region)
        identity = session.client("sts").get_caller_identity()
        extra["account"] = identity.get("Account")
        extra["arn"] = identity.get("Arn")
    except NoCredentialsError:
        return TTPResult(ok=False, error="no AWS credentials", started_at=started, finished_at=time.time())
    except (BotoCoreError, ClientError) as exc:
        return TTPResult(ok=False, error=f"sts failed: {exc}", started_at=started, finished_at=time.time())

    try:
        ec2 = session.client("ec2")
        instance_ids: list[str] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for r in page.get("Reservations", []):
                for i in r.get("Instances", []):
                    instance_ids.append(i.get("InstanceId", ""))
        extra["ec2_instance_count"] = len(instance_ids)
        extra["ec2_sample"] = instance_ids[:10]
    except (BotoCoreError, ClientError) as exc:
        extra["ec2_error"] = str(exc)[:300]

    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        names = [b.get("Name", "") for b in buckets]
        extra["s3_bucket_count"] = len(names)
        extra["s3_sample"] = names[:10]
    except (BotoCoreError, ClientError) as exc:
        extra["s3_error"] = str(exc)[:300]

    ok = "ec2_error" not in extra or "s3_error" not in extra
    return TTPResult(
        ok=ok,
        output=(
            f"AWS account={extra.get('account')} region={region} "
            f"ec2={extra.get('ec2_instance_count', 'err')} s3={extra.get('s3_bucket_count', 'err')}"
        ),
        started_at=started,
        finished_at=time.time(),
        extra=extra,
    )


def _run_gcp(params: dict[str, Any], started: float) -> TTPResult:
    try:
        from google.cloud import resourcemanager_v3  # type: ignore[import-not-found,import-untyped]
        from google.api_core.exceptions import GoogleAPIError  # type: ignore[import-not-found,import-untyped]
    except ImportError:
        return TTPResult(
            ok=False,
            error="google-cloud-resource-manager missing; install via: pip install -e \".[gcp]\"",
            started_at=started,
            finished_at=time.time(),
        )

    extra: dict[str, Any] = {"provider": "gcp"}
    parent_org_id: str | None = params.get("organization_id")

    try:
        client = resourcemanager_v3.ProjectsClient()
        if parent_org_id:
            request = resourcemanager_v3.SearchProjectsRequest(query=f"parent:organizations/{parent_org_id}")
        else:
            request = resourcemanager_v3.SearchProjectsRequest()
        projects = []
        for p in client.search_projects(request=request):
            projects.append({"project_id": p.project_id, "name": p.display_name, "state": p.state.name})
            if len(projects) >= 50:
                break
        extra["project_count"] = len(projects)
        extra["projects_sample"] = projects[:10]
    except GoogleAPIError as exc:
        return TTPResult(
            ok=False,
            error=f"gcp read failed: {str(exc)[:300]}",
            started_at=started,
            finished_at=time.time(),
            extra=extra,
        )
    except Exception as exc:
        return TTPResult(
            ok=False,
            error=f"gcp credential / init failed: {str(exc)[:300]}",
            started_at=started,
            finished_at=time.time(),
        )

    return TTPResult(
        ok=True,
        output=f"GCP projects={extra['project_count']}",
        started_at=started,
        finished_at=time.time(),
        extra=extra,
    )


def _run_azure(params: dict[str, Any], started: float) -> TTPResult:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]
        from azure.mgmt.resource import ResourceManagementClient  # type: ignore[import-not-found]
        from azure.mgmt.resource.subscriptions import SubscriptionClient  # type: ignore[import-not-found]
    except ImportError:
        return TTPResult(
            ok=False,
            error="azure SDK missing; install via: pip install -e \".[azure]\"",
            started_at=started,
            finished_at=time.time(),
        )

    subscription_id: str | None = params.get("subscription_id")
    extra: dict[str, Any] = {"provider": "azure"}

    try:
        cred = DefaultAzureCredential()
    except Exception as exc:  # pragma: no cover
        return TTPResult(ok=False, error=f"azure credential init failed: {exc}", started_at=started, finished_at=time.time())

    try:
        if not subscription_id:
            sub_client = SubscriptionClient(cred)
            subs = list(sub_client.subscriptions.list())
            if not subs:
                return TTPResult(ok=False, error="no Azure subscriptions visible", started_at=started, finished_at=time.time())
            subscription_id = subs[0].subscription_id
        extra["subscription_id"] = subscription_id

        rm = ResourceManagementClient(cred, subscription_id)
        rg_names = [rg.name for rg in rm.resource_groups.list()]
        extra["resource_group_count"] = len(rg_names)
        extra["resource_groups_sample"] = rg_names[:10]
    except Exception as exc:  # broad on purpose: azure SDK exceptions are wide
        return TTPResult(
            ok=False,
            error=f"azure read failed: {str(exc)[:300]}",
            started_at=started,
            finished_at=time.time(),
            extra=extra,
        )

    return TTPResult(
        ok=True,
        output=f"Azure subscription={subscription_id} resource_groups={extra['resource_group_count']}",
        started_at=started,
        finished_at=time.time(),
        extra=extra,
    )


class T1580CloudInfraDiscovery(TTP):
    attack_id = "T1580"
    name = "Cloud Infrastructure Discovery (multi-provider, sim)"
    description = "Read-only inventory across AWS or Azure (provider param)"
    tactic = "discovery"
    supported_platforms = ("windows", "linux", "darwin")

    def run(self, params: dict[str, Any]) -> TTPResult:
        started = time.time()
        provider = str(params.get("provider", "aws")).lower()
        if provider == "aws":
            return _run_aws(params, started)
        if provider == "azure":
            return _run_azure(params, started)
        if provider == "gcp":
            return _run_gcp(params, started)
        return TTPResult(
            ok=False,
            error=f"unsupported provider '{provider}', expected aws|azure|gcp",
            started_at=started,
            finished_at=time.time(),
        )

    def sigma_rule(self) -> dict[str, Any]:
        return {
            "title": "Cloud Discovery API Burst (APT Simulator T1580)",
            "id": "a1580000-0000-0000-0000-000000001580",
            "status": "experimental",
            "description": "Detects bursts of read-only cloud discovery API calls.",
            "references": ["https://attack.mitre.org/techniques/T1580"],
            "tags": ["attack.discovery", "attack.t1580"],
            "logsource": {"product": "cloud"},
            "detection": {
                "selection_aws": {
                    "eventName": ["DescribeInstances", "ListBuckets", "GetCallerIdentity"],
                },
                "selection_azure": {
                    "operationName|contains": ["resourceGroups/read", "subscriptions/read"],
                },
                "selection_gcp": {
                    "methodName|contains": [
                        "google.cloud.resourcemanager",
                        "compute.instances.list",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "falsepositives": ["IaC tooling", "Inventory scanners"],
            "level": "low",
        }

    def synthetic_events(self, params, result=None):  # type: ignore[override]
        provider = str(params.get("provider", "aws")).lower()
        if provider == "aws":
            return [
                {"category": "cloud", "eventName": "DescribeInstances", "readOnly": True},
                {"category": "cloud", "eventName": "ListBuckets", "readOnly": True},
            ]
        if provider == "azure":
            return [{"category": "cloud", "operationName": "Microsoft.Resources/resourceGroups/read"}]
        if provider == "gcp":
            return [{"category": "cloud", "methodName": "google.cloud.resourcemanager.v3.Projects.SearchProjects"}]
        return []


registry.register(T1580CloudInfraDiscovery())
