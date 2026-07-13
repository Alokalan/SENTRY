"""
Day 2: IAM misconfiguration scanner.
Detects wildcard-permission policies (inline + attached), AWS-managed
AdministratorAccess attachments, and missing MFA on IAM users.
Composite risk score (0-100) per user, Rich terminal report + JSON export.
"""

import json
import boto3
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv("config/.env")

console = Console()
iam = boto3.client("iam")

WILDCARD_ACTION_WEIGHT = 40
WILDCARD_RESOURCE_WEIGHT = 30
ADMIN_POLICY_WEIGHT = 25
NO_MFA_WEIGHT = 20


def get_policy_document(policy_arn):
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = policy["DefaultVersionId"]
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    return version["PolicyVersion"]["Document"]


def statements_from_document(document):
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return statements


def check_wildcards(statements):
    wildcard_action = False
    wildcard_resource = False
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions:
            wildcard_action = True
        if "*" in resources:
            wildcard_resource = True
    return wildcard_action, wildcard_resource


def scan_user_policies(user_name):
    findings = []

    inline_policy_names = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    for policy_name in inline_policy_names:
        doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
        wildcard_action, wildcard_resource = check_wildcards(statements_from_document(doc))
        if wildcard_action or wildcard_resource:
            findings.append({
                "type": "inline_policy",
                "policy_name": policy_name,
                "wildcard_action": wildcard_action,
                "wildcard_resource": wildcard_resource,
            })

    attached = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
    for policy in attached:
        if policy["PolicyName"] == "AdministratorAccess":
            findings.append({
                "type": "attached_policy",
                "policy_name": policy["PolicyName"],
                "wildcard_action": True,
                "wildcard_resource": True,
                "note": "AWS managed AdministratorAccess policy",
            })
            continue
        doc = get_policy_document(policy["PolicyArn"])
        wildcard_action, wildcard_resource = check_wildcards(statements_from_document(doc))
        if wildcard_action or wildcard_resource:
            findings.append({
                "type": "attached_policy",
                "policy_name": policy["PolicyName"],
                "wildcard_action": wildcard_action,
                "wildcard_resource": wildcard_resource,
            })

    return findings


def has_mfa(user_name):
    devices = iam.list_mfa_devices(UserName=user_name)["MFADevices"]
    return len(devices) > 0


def calculate_risk_score(policy_findings, mfa_enabled):
    score = 0
    for finding in policy_findings:
        if finding.get("policy_name") == "AdministratorAccess":
            score += ADMIN_POLICY_WEIGHT
        if finding.get("wildcard_action"):
            score += WILDCARD_ACTION_WEIGHT
        if finding.get("wildcard_resource"):
            score += WILDCARD_RESOURCE_WEIGHT
    if not mfa_enabled:
        score += NO_MFA_WEIGHT
    return min(score, 100)


def scan_all_users():
    results = []
    users = iam.list_users()["Users"]
    for user in users:
        user_name = user["UserName"]
        policy_findings = scan_user_policies(user_name)
        mfa_enabled = has_mfa(user_name)
        risk_score = calculate_risk_score(policy_findings, mfa_enabled)
        results.append({
            "user_name": user_name,
            "mfa_enabled": mfa_enabled,
            "policy_findings": policy_findings,
            "risk_score": risk_score,
        })
    return results


def risk_level(score):
    if score >= 70:
        return "[bold red]HIGH[/bold red]"
    if score >= 40:
        return "[yellow]MEDIUM[/yellow]"
    if score > 0:
        return "[green]LOW[/green]"
    return "[dim]NONE[/dim]"


def print_report(results):
    table = Table(title="IAM Scanner — Findings")
    table.add_column("User")
    table.add_column("MFA")
    table.add_column("Findings")
    table.add_column("Risk Score")
    table.add_column("Level")

    for entry in results:
        mfa_display = "[green]Yes[/green]" if entry["mfa_enabled"] else "[red]No[/red]"
        finding_summary = ", ".join(f["policy_name"] for f in entry["policy_findings"]) or "-"
        table.add_row(
            entry["user_name"],
            mfa_display,
            finding_summary,
            str(entry["risk_score"]),
            risk_level(entry["risk_score"]),
        )

    console.print(table)


def export_json(results, path="reports/iam_scan_results.json"):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Full results exported to {path}[/dim]")


if __name__ == "__main__":
    console.print("[bold cyan]Running IAM misconfiguration scan...[/bold cyan]\n")
    scan_results = scan_all_users()
    print_report(scan_results)
    export_json(scan_results)
