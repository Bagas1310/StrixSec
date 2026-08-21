"""
CLI Subcommands for StrixSec Finding Management System.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from strixsec.core.errors import StrixSecError
from strixsec.storage.database import DatabaseManager

findings_app = typer.Typer(
    name="findings",
    help="Manage, filter, and update persistent security assessment findings.",
    no_args_is_help=True,
)

console = Console()


@findings_app.command(name="list")
def list_findings(
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL).",
    ),
    status: str | None = typer.Option(
        None,
        "--status",
        help="Filter by status (OPEN, CONFIRMED, FALSE_POSITIVE, ACCEPTED, FIXED).",
    ),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (SECURITY_HEADER, TLS, COOKIE, METADATA).",
    ),
) -> None:
    """List persistent findings with optional filtering options."""
    db = DatabaseManager()
    try:
        findings = db.list_findings(severity=severity, status=status, category=category)
        if not findings:
            console.print(
                "[yellow]No findings matching specified filters "
                "were found in the database.[/yellow]"
            )
            return

        table = Table(title="StrixSec Security Assessment Findings", show_header=True)
        table.add_column("Finding ID", style="bold cyan")
        table.add_column("Title", style="bold")
        table.add_column("Asset", style="cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Severity", style="yellow")
        table.add_column("Status", style="green")

        for f in findings:
            table.add_row(
                f.id,
                f.title,
                f.asset,
                f.category,
                f.severity,
                f.status,
            )

        console.print(table)
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Database error: {err.message}")
        raise typer.Exit(code=1) from err


@findings_app.command(name="show")
def show_finding(
    finding_id: str = typer.Argument(..., help="Finding ID string (e.g. STRX-0001)."),
) -> None:
    """Display detailed information, evidence, and remediation for a specific finding."""
    db = DatabaseManager()
    try:
        finding = db.get_finding(finding_id)
        if not finding:
            console.print(
                f"[bold red][-][/bold red] Finding '[cyan]{finding_id}[/cyan]' not found."
            )
            raise typer.Exit(code=1)

        panel_content = f"""[bold]Finding ID:[/bold] {finding.id}
[bold]Title:[/bold] {finding.title}
[bold]Asset:[/bold] {finding.asset}
[bold]Category:[/bold] {finding.category}
[bold]Severity:[/bold] [yellow]{finding.severity}[/yellow]
[bold]Confidence:[/bold] {finding.confidence}
[bold]Status:[/bold] [bold green]{finding.status}[/bold green]
[bold]Created At:[/bold] {finding.created_at}

[bold underline]Description:[/bold underline]
{finding.description}

[bold underline]Impact:[/bold underline]
{finding.impact or "N/A"}

[bold underline]Remediation:[/bold underline]
{finding.remediation or "N/A"}
"""
        console.print(Panel(panel_content, title=f"Finding Details: {finding.id}", expand=False))

        if finding.evidence:
            ev_table = Table(title="Supporting Evidence (Sanitized)", show_header=True)
            ev_table.add_column("Type", style="magenta")
            ev_table.add_column("Source", style="cyan")
            ev_table.add_column("Sanitized Payload", style="dim")
            for ev in finding.evidence:
                ev_table.add_row(ev.type, ev.source, ev.sanitized_value)
            console.print(ev_table)

    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Database error: {err.message}")
        raise typer.Exit(code=1) from err


@findings_app.command(name="update")
def update_finding(
    finding_id: str = typer.Argument(..., help="Finding ID to update (e.g. STRX-0001)."),
    status: str = typer.Option(
        ...,
        "--status",
        "-s",
        help="New lifecycle status (OPEN, CONFIRMED, FALSE_POSITIVE, ACCEPTED, FIXED).",
    ),
) -> None:
    """Update the lifecycle status of a persistent finding."""
    db = DatabaseManager()
    try:
        updated = db.update_finding_status(finding_id, status)
        if updated:
            console.print(
                f"[bold green][+][/bold green] Finding [cyan]{finding_id}[/cyan] "
                f"updated to status: [bold green]{status.upper()}[/bold green]"
            )
        else:
            console.print(
                f"[bold red][-][/bold red] Finding '[cyan]{finding_id}[/cyan]' not found."
            )
            raise typer.Exit(code=1)
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Update failed: {err.message}")
        raise typer.Exit(code=1) from err
