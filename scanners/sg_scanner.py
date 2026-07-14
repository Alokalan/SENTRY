"""
Day 4: Security Group / network scanner.
Detects security group rules open to the world (0.0.0.0/0 or ::/0),
flags sensitive ports (SSH, RDP, common databases) as higher severity,
and lists unused (unattached) Elastic Network Interfaces.
Composite risk score (0-100) per security group, Rich terminal report + JSON export.
"""

import json
import boto3
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv("config/.env")

console = Console()
ec2 = boto3.client("ec2")

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
}

CRITICAL_WEIGHT = 60
HIGH_WEIGHT = 50
MEDIUM_WEIGHT = 25


def is_open_to_world(permission):
    ip_ranges = permission.get("IpRanges", [])
    ipv6_ranges = permission.get("Ipv6Ranges", [])
    if any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges):
        return True
    if any(r.get("CidrIpv6") == "::/0" for r in ipv6_ranges):
        return True
    return False


def sensitive_port_hit(from_port, to_port):
    if from_port is None or to_port is None:
        return None
    for port, name in SENSITIVE_PORTS.items():
        if from_port <= port <= to_port:
            return name
    return None


def get_open_findings(security_group):
    findings = []
    for permission in security_group.get("IpPermissions", []):
        if not is_open_to_world(permission):
            continue

        protocol = permission.get("IpProtocol")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        if protocol == "-1":
            findings.append({
                "protocol": "ALL",
                "port_range": "ALL",
                "severity": "critical",
                "sensitive_service": None,
            })
            continue

        service = sensitive_port_hit(from_port, to_port)
        port_range = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
        findings.append({
            "protocol": protocol,
            "port_range": port_range,
            "severity": "high" if service else "medium",
            "sensitive_service": service,
        })

    return findings


def calculate_sg_risk(findings):
    score = 0
    for finding in findings:
        if finding["severity"] == "critical":
            score += CRITICAL_WEIGHT
        elif finding["severity"] == "high":
            score += HIGH_WEIGHT
        else:
            score += MEDIUM_WEIGHT
    return min(score, 100)


def risk_level(score):
    if score >= 70:
        return "[bold red]HIGH[/bold red]"
    if score >= 40:
        return "[yellow]MEDIUM[/yellow]"
    if score > 0:
        return "[green]LOW[/green]"
    return "[dim]NONE[/dim]"


def scan_security_groups():
    results = []
    security_groups = ec2.describe_security_groups()["SecurityGroups"]
    for sg in security_groups:
        findings = get_open_findings(sg)
        results.append({
            "group_id": sg["GroupId"],
            "group_name": sg.get("GroupName", ""),
            "findings": findings,
            "risk_score": calculate_sg_risk(findings),
        })
    return results


def scan_unused_enis():
    interfaces = ec2.describe_network_interfaces()["NetworkInterfaces"]
    unused = [eni for eni in interfaces if eni.get("Status") == "available"]
    return [
        {
            "eni_id": eni["NetworkInterfaceId"],
            "vpc_id": eni.get("VpcId", "-"),
            "availability_zone": eni.get("AvailabilityZone", "-"),
            "status": eni.get("Status"),
        }
        for eni in unused
    ]


def print_sg_report(results):
    table = Table(title="Security Group Scanner — Findings")
    table.add_column("Group ID")
    table.add_column("Name")
    table.add_column("Open Rules")
    table.add_column("Risk Score")
    table.add_column("Level")

    for entry in results:
        rule_summary = ", ".join(
            f'{f["sensitive_service"] or f["protocol"]}:{f["port_range"]}'
            for f in entry["findings"]
        ) or "-"
        table.add_row(
            entry["group_id"],
            entry["group_name"],
            rule_summary,
            str(entry["risk_score"]),
            risk_level(entry["risk_score"]),
        )

    console.print(table)


def print_eni_report(unused_enis):
    if not unused_enis:
        console.print("\n[green]No unused (unattached) network interfaces found.[/green]")
        return

    table = Table(title="Unused Network Interfaces")
    table.add_column("ENI ID")
    table.add_column("VPC")
    table.add_column("Availability Zone")
    table.add_column("Status")

    for eni in unused_enis:
        table.add_row(eni["eni_id"], eni["vpc_id"], eni["availability_zone"], eni["status"])

    console.print("\n")
    console.print(table)


def export_json(sg_results, eni_results, path="reports/sg_scan_results.json"):
    combined = {"security_groups": sg_results, "unused_enis": eni_results}
    with open(path, "w") as f:
        json.dump(combined, f, indent=2)
    console.print(f"\n[dim]Full results exported to {path}[/dim]")


if __name__ == "__main__":
    console.print("[bold cyan]Running Security Group / network scan...[/bold cyan]\n")
    sg_results = scan_security_groups()
    eni_results = scan_unused_enis()
    print_sg_report(sg_results)
    print_eni_report(eni_results)
    export_json(sg_results, eni_results)
