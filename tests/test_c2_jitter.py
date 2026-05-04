from __future__ import annotations

import statistics

from ttps.command_and_control.t1071_001_http_c2 import (
    UA_PROFILES,
    _is_lab_target,
    _jittered_delay,
    _within_window,
)


def test_jitter_uniform_bounds() -> None:
    samples = [_jittered_delay(1.0, 0.5, "uniform", i) for i in range(200)]
    assert all(1.0 <= s <= 1.5 + 1e-6 for s in samples)


def test_jitter_exponential_positive() -> None:
    samples = [_jittered_delay(1.0, 0.5, "exponential", i) for i in range(200)]
    assert all(s >= 1.0 for s in samples)
    # Mean of exponential(1/jitter) is jitter, so total mean ~ base + jitter.
    assert statistics.mean(samples) > 1.0


def test_jitter_normal_no_negatives() -> None:
    samples = [_jittered_delay(1.0, 0.4, "normal", i) for i in range(200)]
    assert all(s >= 0 for s in samples)


def test_jitter_zero_returns_base() -> None:
    assert _jittered_delay(1.0, 0.0, "uniform", 0) == 1.0


def test_lab_target_loopback() -> None:
    assert _is_lab_target("http://127.0.0.1:8000/")
    assert _is_lab_target("http://10.1.2.3/")
    assert _is_lab_target("http://192.168.1.10/")
    assert not _is_lab_target("http://8.8.8.8/")


def test_within_window_simple() -> None:
    # Window covering all hours.
    assert _within_window([0, 24])
    # Empty.
    assert _within_window(None)


def test_ua_profiles_present() -> None:
    assert "default" in UA_PROFILES
    assert "stealth" in UA_PROFILES
    assert "noisy" in UA_PROFILES
    assert all(len(v) > 0 for v in UA_PROFILES.values())
