"""
CLI Subcommands for StrixSec Recon Subsystem.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from strixsec.core.errors import ScopeValidationError, StrixSecError
from strixsec.recon.engine import ReconEngine

recon_app = typer.Typer(
    name="recon",
    help="Perform safe reconnaissance (DNS, HTTP, Technology Fingerprinting).",
    no_args_is_help=True,
)

console = Console()


@recon_app.command(name="dns")
def recon_dns(
    target: str = typer.Argument(..., help="Authorized target domain or IP."),
) -> None:
    """Perform non-destructive DNS queries for authorized target."""
    engine = ReconEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] DNS analysis started...")

        dns_res = engine.run_dns(target)

        table = Table(title=f"DNS Records for {norm_target}", show_header=True)
        table.add_column("Type", style="magenta")
        table.add_column("TTL", style="dim")
        table.add_column("Value", style="cyan")

        for rec in dns_res.records:
            table.add_row(rec.record_type, str(rec.ttl or "-"), rec.value)

        console.print(table)
        console.print(f"Status: [bold green]{dns_res.status}[/bold green]")
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Recon error: {err.message}")
        raise typer.Exit(code=1) from err


@recon_app.command(name="http")
def recon_http(
    target: str = typer.Argument(..., help="Authorized target domain, IP, or URL."),
) -> None:
    """Perform safe HTTP/HTTPS inspection for authorized target."""
    engine = ReconEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] HTTP analysis started...")

        http_res = engine.run_http(target)

        if http_res.error:
            console.print(f"[bold yellow][-][/bold yellow] HTTP Analysis Warning: {http_res.error}")
            return

        table = Table(title=f"HTTP Inspection for {norm_target}", show_header=True)
        table.add_column("Attribute", style="bold")
        table.add_column("Value", style="cyan")

        table.add_row("URL", http_res.url)
        table.add_row("Final URL", http_res.final_url)
        table.add_row("Status Code", str(http_res.status_code))
        table.add_row("Content-Type", http_res.content_type or "N/A")
        table.add_row("Page Title", http_res.page_title or "N/A")
        table.add_row("Server", http_res.server or "N/A")
        table.add_row("HTTPS Available", str(http_res.https_available))
        table.add_row("Redirect Hops", str(len(http_res.redirect_chain)))

        console.print(table)
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Recon error: {err.message}")
        raise typer.Exit(code=1) from err


@recon_app.command(name="tech")
def recon_tech(
    target: str = typer.Argument(..., help="Authorized target domain, IP, or URL."),
) -> None:
    """Passively detect technologies for authorized target."""
    engine = ReconEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] Technology detection started...")

        tech_res = engine.run_tech(target)

        table = Table(title=f"Detected Technologies for {norm_target}", show_header=True)
        table.add_column("Technology", style="bold green")
        table.add_column("Category", style="magenta")
        table.add_column("Confidence", style="yellow")
        table.add_column("Matched Indicator", style="dim")

        for match in tech_res.detected_technologies:
            table.add_row(match.name, match.category, match.confidence, match.matched_indicator)

        console.print(table)
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Recon error: {err.message}")
        raise typer.Exit(code=1) from err


@recon_app.command(name="all")
def recon_all(
    target: str = typer.Argument(..., help="Authorized target domain, IP, or URL."),
) -> None:
    """Run full safe reconnaissance suite (DNS, HTTP, Tech) for authorized target."""
    engine = ReconEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] Full reconnaissance suite started...")

        asset = engine.run_full_recon(target)

        # Render summary
        console.print(f"[bold green]Reconnaissance completed for {asset.target}[/bold green]")
        if asset.dns_info:
            console.print(f"  - Resolved DNS records: {len(asset.dns_info.records)}")
        if asset.http_info:
            console.print(
                f"  - Final HTTP URL: {asset.http_info.final_url} "
                f"(Status: {asset.http_info.status_code})"
            )
        if asset.tech_info:
            console.print(
                f"  - Detected technologies: {len(asset.tech_info.detected_technologies)}"
            )

    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Recon error: {err.message}")
        raise typer.Exit(code=1) from err
