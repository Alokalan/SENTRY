"""
Day 3: S3 misconfiguration scanner.
Detects public bucket access, missing encryption, missing versioning,
and missing access logging. Composite risk score (0-100) per bucket,
Rich terminal report + JSON export.
"""

import json
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv("config/.env")

console = Console()
s3 = boto3.client("s3")

PUBLIC_ACCESS_WEIGHT = 40
NO_ENCRYPTION_WEIGHT = 25
NO_VERSIONING_WEIGHT = 20
NO_LOGGING_WEIGHT = 15


def is_bucket_public(bucket_name):
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if status["PolicyStatus"]["IsPublic"]:
            return True
    except ClientError:
        pass

    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl["Grants"]:
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
    except ClientError:
        pass

    return False


def has_encryption(bucket_name):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError:
        return False


def has_versioning(bucket_name):
    response = s3.get_bucket_versioning(Bucket=bucket_name)
    return response.get("Status") == "Enabled"


def has_logging(bucket_name):
    response = s3.get_bucket_logging(Bucket=bucket_name)
    return "LoggingEnabled" in response


def calculate_risk_score(is_public, encrypted, versioned, logged):
    score = 0
    if is_public:
        score += PUBLIC_ACCESS_WEIGHT
    if not encrypted:
        score += NO_ENCRYPTION_WEIGHT
    if not versioned:
        score += NO_VERSIONING_WEIGHT
    if not logged:
        score += NO_LOGGING_WEIGHT
    return min(score, 100)


def risk_level(score):
    if score >= 70:
        return "[bold red]HIGH[/bold red]"
    if score >= 40:
        return "[yellow]MEDIUM[/yellow]"
    if score > 0:
        return "[green]LOW[/green]"
    return "[dim]NONE[/dim]"


def scan_all_buckets():
    results = []
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        is_public = is_bucket_public(name)
        encrypted = has_encryption(name)
        versioned = has_versioning(name)
        logged = has_logging(name)
        risk_score = calculate_risk_score(is_public, encrypted, versioned, logged)
        results.append({
            "bucket_name": name,
            "is_public": is_public,
            "encrypted": encrypted,
            "versioned": versioned,
            "logging_enabled": logged,
            "risk_score": risk_score,
        })
    return results


def print_report(results):
    table = Table(title="S3 Scanner — Findings")
    table.add_column("Bucket")
    table.add_column("Public")
    table.add_column("Encrypted")
    table.add_column("Versioned")
    table.add_column("Logging")
    table.add_column("Risk Score")
    table.add_column("Level")

    for entry in results:
        public_display = "[red]Yes[/red]" if entry["is_public"] else "[green]No[/green]"
        enc_display = "[green]Yes[/green]" if entry["encrypted"] else "[red]No[/red]"
        ver_display = "[green]Yes[/green]" if entry["versioned"] else "[yellow]No[/yellow]"
        log_display = "[green]Yes[/green]" if entry["logging_enabled"] else "[yellow]No[/yellow]"
        table.add_row(
            entry["bucket_name"],
            public_display,
            enc_display,
            ver_display,
            log_display,
            str(entry["risk_score"]),
            risk_level(entry["risk_score"]),
        )

    console.print(table)


def export_json(results, path="reports/s3_scan_results.json"):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Full results exported to {path}[/dim]")


if __name__ == "__main__":
    console.print("[bold cyan]Running S3 misconfiguration scan...[/bold cyan]\n")
    scan_results = scan_all_buckets()
    print_report(scan_results)
    export_json(scan_results)
