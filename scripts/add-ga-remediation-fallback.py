#!/usr/bin/env python3
"""
Add a GA (generally available) remediation fallback to every playbook that
calls the Microsoft Graph beta analyzedEmails/remediate endpoint.

The Graph remediate action is beta-only (not production-supported). This
adds a backup path: when the beta call Fails or TimesOut, the playbook POSTs
the same message set to a parameterised webhook (`GaRemediationWebhookUrl`)
that an operator wires to an Azure Automation runbook running the GA
Security & Compliance path (New-ComplianceSearch + New-ComplianceSearchAction
-Purge). If the URL parameter is left empty, the fallback is skipped.

Idempotent: re-running detects the already-injected param/action and no-ops.
"""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLAYBOOKS = [
    "P1-phish-remediate",
    "P1b-phish-remediate-bulk",
    "P2-ti-sweep-remediate",
    "P4-forward-trace-remediate",
    "P5-dl-expand-remediate",
    "P6-two-stage-approval-vip",
]

PARAM_NAME = "GaRemediationWebhookUrl"
FALLBACK_NAME = "Fallback_GA_ComplianceSearch_purge"


def find_takeaction(node):
    """Return (actions_map, action_name, action_obj) for the Graph remediate call."""
    if isinstance(node, dict):
        for k, v in node.items():
            if (
                isinstance(v, dict)
                and v.get("type") == "Http"
                and isinstance(v.get("inputs"), dict)
                and "analyzedEmails/remediate" in str(v["inputs"].get("uri", ""))
            ):
                return node, k, v
        for v in node.values():
            r = find_takeaction(v)
            if r:
                return r
    elif isinstance(node, list):
        for v in node:
            r = find_takeaction(v)
            if r:
                return r
    return None


def process(folder: str):
    path = REPO / "automation" / "logic-apps" / folder / "playbook.json"
    obj = json.loads(path.read_text())

    # 1. ARM-level parameter.
    obj.setdefault("parameters", {})
    if PARAM_NAME not in obj["parameters"]:
        obj["parameters"][PARAM_NAME] = {
            "type": "string",
            "defaultValue": "",
            "metadata": {
                "description": "Optional HTTPS webhook (e.g. an Azure Automation runbook) that performs the GA Security & Compliance remediation (New-ComplianceSearchAction -Purge). Called only if the Graph beta remediate call fails. Leave empty to disable the fallback."
            },
        }

    definition = obj["resources"][0]["properties"]["definition"]

    # 2. Workflow-definition parameter mirroring the ARM parameter.
    definition.setdefault("parameters", {})
    if PARAM_NAME not in definition["parameters"]:
        definition["parameters"][PARAM_NAME] = {
            "type": "String",
            "defaultValue": f"[parameters('{PARAM_NAME}')]",
        }

    # 3. Inject the fallback action next to the take-action call.
    found = find_takeaction(definition["actions"])
    if not found:
        raise SystemExit(f"{folder}: no analyzedEmails/remediate action found")
    actions_map, action_name, action_obj = found
    primary_body = action_obj["inputs"]["body"]

    if FALLBACK_NAME not in actions_map:
        actions_map[FALLBACK_NAME] = {
            "type": "If",
            "runAfter": {action_name: ["Failed", "TimedOut"]},
            "expression": {
                "and": [
                    {"not": {"equals": [f"@parameters('{PARAM_NAME}')", ""]}}
                ]
            },
            "actions": {
                "Post_GA_purge_request": {
                    "type": "Http",
                    "inputs": {
                        "method": "POST",
                        "uri": f"@parameters('{PARAM_NAME}')",
                        "headers": {"Content-Type": "application/json"},
                        "body": {
                            "method": "ComplianceSearchAction-Purge",
                            "purgeType": "SoftDelete",
                            "reason": f"GA fallback after Graph beta remediate failed in {folder}",
                            "action": primary_body.get("action"),
                            "displayName": primary_body.get("displayName"),
                            "analyzedEmails": primary_body.get("analyzedEmails"),
                        },
                    },
                }
            },
        }

    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")

    # 4. parameters.example.json.
    ex_path = path.parent / "parameters.example.json"
    if ex_path.exists():
        ex = json.loads(ex_path.read_text())
        ex.setdefault("parameters", {})
        if PARAM_NAME not in ex["parameters"]:
            ex["parameters"][PARAM_NAME] = {"value": ""}
            ex_path.write_text(json.dumps(ex, indent=2, ensure_ascii=False) + "\n")

    return action_name


def main():
    for folder in PLAYBOOKS:
        an = process(folder)
        print(f"{folder}: fallback added after '{an}'")


if __name__ == "__main__":
    main()
