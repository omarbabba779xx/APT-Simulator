from __future__ import annotations

from orchestrator.detection import evaluate


def test_endswith_match() -> None:
    rule = {"detection": {"selection": {"Image|endswith": ["\\whoami.exe"]}, "condition": "selection"}}
    assert evaluate(rule, {"Image": "C:\\Windows\\System32\\whoami.exe"})
    assert not evaluate(rule, {"Image": "C:\\Windows\\System32\\hostname.exe"})


def test_contains_match() -> None:
    rule = {"detection": {"selection": {"CommandLine|contains": ["lsass"]}, "condition": "selection"}}
    assert evaluate(rule, {"CommandLine": "tasklist | findstr lsass"})
    assert not evaluate(rule, {"CommandLine": "ls -la"})


def test_contains_all_modifier() -> None:
    rule = {"detection": {"selection": {"CommandLine|contains|all": ["dir", "/s"]}, "condition": "selection"}}
    assert evaluate(rule, {"CommandLine": "dir /s C:\\"})
    assert not evaluate(rule, {"CommandLine": "dir C:\\"})


def test_one_of_selections() -> None:
    rule = {
        "detection": {
            "selection_a": {"Image|endswith": ["\\a.exe"]},
            "selection_b": {"Image|endswith": ["\\b.exe"]},
            "condition": "1 of selection_*",
        }
    }
    assert evaluate(rule, {"Image": "x\\a.exe"})
    assert evaluate(rule, {"Image": "x\\b.exe"})
    assert not evaluate(rule, {"Image": "x\\c.exe"})


def test_all_of_selections() -> None:
    rule = {
        "detection": {
            "selection_a": {"CommandLine|contains": ["foo"]},
            "selection_b": {"CommandLine|contains": ["bar"]},
            "condition": "all of selection_*",
        }
    }
    assert evaluate(rule, {"CommandLine": "foo bar"})
    assert not evaluate(rule, {"CommandLine": "foo"})


def test_boolean_field() -> None:
    rule = {
        "detection": {
            "selection": {"eventName": "DescribeInstances", "readOnly": True},
            "condition": "selection",
        }
    }
    assert evaluate(rule, {"eventName": "DescribeInstances", "readOnly": True})
    assert not evaluate(rule, {"eventName": "DescribeInstances", "readOnly": False})


def test_missing_field_no_match() -> None:
    rule = {"detection": {"selection": {"Image|endswith": [".exe"]}, "condition": "selection"}}
    assert not evaluate(rule, {"OtherField": "value"})
