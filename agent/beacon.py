"""Beacon loop: register, poll, execute, report."""
from __future__ import annotations

import os
import platform
import random
import time
from typing import Any

import httpx

from . import runtime, safety


class Beacon:
    def __init__(
        self,
        server: str,
        interval: float = 5.0,
        jitter: float = 2.0,
        ttl_seconds: int = 14400,
        max_failures: int = 5,
        auth_token: str | None = None,
    ) -> None:
        self.server = server.rstrip("/")
        self.interval = interval
        self.jitter = jitter
        self.ttl_seconds = ttl_seconds
        self.max_failures = max_failures
        self.agent_id: str | None = None
        self.public_key = None
        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
        self.client = httpx.Client(timeout=20.0, headers=headers)
        self.failures = 0
        self.start_time = time.time()

    def register(self) -> None:
        body = {
            "hostname": platform.node(),
            "platform": platform.system().lower(),
            "pid": os.getpid(),
        }
        resp = self.client.post(f"{self.server}/agents/register", json=body)
        resp.raise_for_status()
        data = resp.json()
        self.agent_id = data["agent_id"]
        pub_pem = data.get("public_key_pem")
        if pub_pem:
            self.public_key = runtime.load_public_key(pub_pem)

    def _sleep_with_jitter(self) -> None:
        time.sleep(self.interval + random.uniform(0, self.jitter))

    def _ttl_expired(self) -> bool:
        return (time.time() - self.start_time) > self.ttl_seconds

    def _beacon_once(self) -> None:
        assert self.agent_id
        resp = self.client.post(
            f"{self.server}/agents/beacon",
            json={"agent_id": self.agent_id, "platform": platform.system().lower()},
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("killswitch"):
            raise SystemExit("orchestrator killswitch active")
        task = data.get("task")
        if not task:
            return
        result = self._execute_task(task)
        self._report(task["run_id"], task["step_id"], result)

    def _execute_task(self, task: dict[str, Any]) -> dict[str, Any]:
        # Verify signature (if required) — strip the field from a copy first.
        verifier_input = dict(task)
        if not runtime.verify_task(verifier_input, self.public_key):
            return {"ok": False, "output": "", "error": "payload signature invalid"}
        attack_id = task["attack_id"]
        params = task.get("params", {})
        res = runtime.execute(attack_id, params)
        return {
            "ok": res.ok,
            "output": res.output,
            "error": res.error,
        }

    def _report(self, run_id: str, step_id: str, result: dict[str, Any]) -> None:
        assert self.agent_id
        self.client.post(
            f"{self.server}/agents/result",
            json={
                "agent_id": self.agent_id,
                "run_id": run_id,
                "step_id": step_id,
                **result,
            },
        )

    def loop(self) -> None:
        engaged, reason = safety.killswitch_engaged()
        if engaged:
            print(f"[agent] killswitch active before start: {reason}")
            return
        ok, why = safety.host_in_whitelist()
        if not ok:
            print(f"[agent] refusing to run: {why}")
            return
        self.register()
        print(f"[agent] registered as {self.agent_id} on {self.server}")
        while True:
            if self._ttl_expired():
                print("[agent] TTL expired; exiting")
                return
            engaged, reason = safety.killswitch_engaged()
            if engaged:
                print(f"[agent] local killswitch: {reason}; exiting")
                return
            try:
                self._beacon_once()
                self.failures = 0
            except SystemExit as exc:
                print(f"[agent] {exc}")
                return
            except Exception as exc:
                self.failures += 1
                print(f"[agent] beacon error ({self.failures}/{self.max_failures}): {exc}")
                if self.failures >= self.max_failures:
                    print("[agent] max failures reached; exiting")
                    return
            self._sleep_with_jitter()
