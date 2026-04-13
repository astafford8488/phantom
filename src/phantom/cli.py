"""PHANTOM CLI — command-line interface for detection engineering.

Commands:
    phantom analyze    — Run detection pipeline on log files
    phantom rules      — Manage Sigma detection rules
    phantom hunt       — Run autonomous threat hunting
    phantom coverage   — MITRE ATT&CK coverage analysis
    phantom serve      — Start the REST API server
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from phantom.engine import PhantomEngine

console = Console()


def _load_events(path: str) -> list[dict[str, Any]]:
    """Load events from a JSON or JSONL file."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)

    events: list[dict[str, Any]] = []
    text = p.read_text(encoding="utf-8")

    if p.suffix == ".jsonl":
        for line in text.strip().split("\n"):
            if line.strip():
                events.append(json.loads(line))
    else:
        data = json.loads(text)
        if isinstance(data, list):
            events = data
        elif isinstance(data, dict):
            events = [data]

    return events


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """PHANTOM — AI-Powered Detection Engineering & Autonomous Threat Hunting."""
    pass


@main.command()
@click.argument("events_file")
@click.option("--rules", "-r", help="Path to Sigma rules directory or file")
@click.option("--hunt/--no-hunt", default=False, help="Enable autonomous hunting")
@click.option("--output", "-o", help="Output file (JSON)")
def analyze(events_file: str, rules: str | None, hunt: bool, output: str | None) -> None:
    """Run the full detection pipeline on a log file."""
    engine = PhantomEngine()

    if rules:
        loaded = engine.load_rules(rules)
        console.print(f"[green]Loaded {loaded} Sigma rules[/green]")

    events = _load_events(events_file)
    console.print(f"[blue]Analyzing {len(events)} events...[/blue]")

    report = asyncio.run(engine.analyze(events, run_hunting=hunt))

    # Display report
    console.print(Panel(report.summary(), title="PHANTOM Report", border_style="cyan"))

    # Show detections table
    if report.detections:
        table = Table(title="Detections")
        table.add_column("Rule ID", style="dim")
        table.add_column("Name", style="bold")
        table.add_column("Severity", style="red")
        table.add_column("Source")
        table.add_column("Events", justify="right")
        table.add_column("Confidence", justify="right")

        for d in report.detections:
            sev_color = {
                "critical": "red bold", "high": "red",
                "medium": "yellow", "low": "green",
            }.get(d.severity, "dim")
            table.add_row(
                d.rule_id[:12],
                d.rule_name[:50],
                f"[{sev_color}]{d.severity}[/{sev_color}]",
                d.source,
                str(len(d.matched_events)),
                f"{d.confidence:.2f}",
            )
        console.print(table)

    if output:
        Path(output).write_text(json.dumps({
            "total_detections": report.total_detections,
            "incidents": len(report.incidents),
            "hunting_findings": len(report.hunting_findings),
            "elapsed_seconds": report.elapsed_seconds,
            "detections": [
                {"rule_id": d.rule_id, "rule_name": d.rule_name,
                 "severity": d.severity, "source": d.source}
                for d in report.detections
            ],
        }, indent=2))
        console.print(f"[green]Results written to {output}[/green]")


@main.group()
def rules() -> None:
    """Manage Sigma detection rules."""
    pass


@rules.command("load")
@click.argument("path")
def rules_load(path: str) -> None:
    """Load and validate Sigma rules from a directory."""
    from phantom.detection.sigma_engine import SigmaEngine

    engine = SigmaEngine()
    loaded = engine.load_rules(path)
    console.print(f"[green]Loaded {loaded} rules[/green]")

    table = Table(title="Sigma Rules")
    table.add_column("ID", style="dim")
    table.add_column("Title", style="bold")
    table.add_column("Level")
    table.add_column("Status")
    table.add_column("MITRE Techniques")

    for r in engine.list_rules():
        table.add_row(r["id"][:20], r["title"], r["level"], r["status"], r["techniques"])
    console.print(table)


@rules.command("validate")
@click.argument("file_path")
def rules_validate(file_path: str) -> None:
    """Validate a Sigma rule YAML file."""
    from phantom.detection.sigma_engine import SigmaEngine

    text = Path(file_path).read_text(encoding="utf-8")
    engine = SigmaEngine()
    valid, errors = engine.validate_rule(text)

    if valid:
        console.print("[green]✓ Rule is valid[/green]")
    else:
        console.print("[red]✗ Rule validation failed:[/red]")
        for error in errors:
            console.print(f"  [red]• {error}[/red]")


@rules.command("generate")
@click.argument("description")
@click.option("--model", "-m", default="claude-sonnet-4-20250514", help="LLM model to use")
@click.option("--output", "-o", help="Output file for generated rule")
def rules_generate(description: str, model: str, output: str | None) -> None:
    """Generate a Sigma rule from natural language description."""
    from phantom.detection.sigma_engine import SigmaEngine

    engine = SigmaEngine()
    rule_yaml = asyncio.run(engine.generate_from_nl(description, model=model))

    console.print(Panel(rule_yaml, title="Generated Sigma Rule", border_style="green"))

    if output:
        Path(output).write_text(rule_yaml, encoding="utf-8")
        console.print(f"[green]Rule saved to {output}[/green]")


@main.command()
@click.argument("events_file")
@click.option("--rules", "-r", help="Path to Sigma rules for context")
def hunt(events_file: str, rules: str | None) -> None:
    """Run autonomous threat hunting on events."""
    engine = PhantomEngine()
    if rules:
        engine.load_rules(rules)

    events = _load_events(events_file)
    console.print(f"[blue]Hunting across {len(events)} events...[/blue]")

    findings = asyncio.run(engine.hunter.hunt(events))

    if findings:
        table = Table(title="Hunting Findings")
        table.add_column("Type", style="dim")
        table.add_column("Title", style="bold")
        table.add_column("Severity")
        table.add_column("Technique")
        table.add_column("Events", justify="right")
        table.add_column("Confidence", justify="right")

        for f in findings:
            table.add_row(
                f["type"],
                f["title"][:50],
                f["severity"],
                f.get("mitre_technique", ""),
                str(f.get("event_count", 0)),
                f"{f.get('confidence', 0):.2f}",
            )
        console.print(table)
    else:
        console.print("[green]No threats found during hunting.[/green]")


@main.command()
@click.option("--rules", "-r", help="Path to Sigma rules")
def coverage(rules: str | None) -> None:
    """Display MITRE ATT&CK coverage analysis."""
    engine = PhantomEngine()
    if rules:
        engine.load_rules(rules)

    # Collect techniques from loaded rules
    techniques: list[str] = []
    for rule_info in engine.sigma.list_rules():
        techs = rule_info.get("techniques", "")
        if techs:
            techniques.extend(t.strip() for t in techs.split(",") if t.strip())

    report = engine.mitre.coverage_report(techniques)

    console.print(Panel(
        f"Coverage: {report['covered']}/{report['total']} techniques "
        f"({report['percentage']:.1f}%)",
        title="MITRE ATT&CK Coverage",
        border_style="cyan",
    ))

    # By-tactic table
    table = Table(title="Coverage by Tactic")
    table.add_column("Tactic", style="bold")
    table.add_column("Covered", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Coverage", justify="right")

    for tactic, stats in report.get("by_tactic", {}).items():
        pct = stats["percentage"]
        color = "green" if pct > 60 else "yellow" if pct > 30 else "red"
        table.add_row(
            tactic,
            str(stats["covered"]),
            str(stats["total"]),
            f"[{color}]{pct:.0f}%[/{color}]",
        )
    console.print(table)

    # Top gaps
    gaps = report.get("gaps", [])
    if gaps:
        gap_table = Table(title=f"Top Coverage Gaps ({len(gaps)} total)")
        gap_table.add_column("Technique", style="bold")
        gap_table.add_column("Name")
        gap_table.add_column("Tactic")
        gap_table.add_column("Priority")

        for gap in gaps[:10]:
            p_color = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(gap["priority"], "dim")
            gap_table.add_row(
                gap["id"],
                gap["name"],
                gap["tactic"],
                f"[{p_color}]{gap['priority']}[/{p_color}]",
            )
        console.print(gap_table)


@main.command()
@click.option("--host", default="0.0.0.0", help="Bind host")
@click.option("--port", "-p", default=8000, help="Bind port")
@click.option("--rules", "-r", help="Path to Sigma rules to preload")
def serve(host: str, port: int, rules: str | None) -> None:
    """Start the PHANTOM REST API server."""
    import uvicorn
    from phantom.api.server import app, engine as server_engine

    if rules:
        loaded = server_engine.load_rules(rules)
        console.print(f"[green]Preloaded {loaded} Sigma rules[/green]")

    console.print(f"[cyan]Starting PHANTOM API on {host}:{port}[/cyan]")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
