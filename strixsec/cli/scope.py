"""
CLI Commands for StrixSec Scope System.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from strixsec.core.errors import ScopeValidationError, StrixSecError
from strixsec.scope.storage import ScopeStorage
from strixsec.scope.validator import ScopeValidator

scope_app = typer.Typer(
    name="scope",
    help="Manage and validate target authorization scope rules.",
    no_args_is_help=True,
)

console = Console()


@scope_app.command(name="add")
def add_scope(
    target: str = typer.Argument(
        ..., help="Target domain, wildcard (*.domain.com), IPv4, or CIDR range."
    ),
    exclude: bool = typer.Option(
        False, "--exclude", "-e", help="Mark target as an explicit exclusion rule."
    ),
) -> None:
    """Add a target or CIDR range to the active authorization scope."""
    storage = ScopeStorage()
    try:
        entry = storage.add_target(target, is_exclusion=exclude)
        rule_type = "exclusion" if exclude else "allowed target"
        console.print(
            f"[bold green][+][/bold green] Scope {rule_type} added: "
            f"[cyan]{entry.normalized_target}[/cyan]"
        )
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] Error adding target to scope: {err.message}")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Storage error: {err.message}")
        raise typer.Exit(code=1) from err


@scope_app.command(name="list")
def list_scope() -> None:
    """List all currently configured authorization scope rules."""
    storage = ScopeStorage()
    config = storage.load_scope()

    if not config.allowed_targets and not config.excluded_targets:
        console.print(
            "[yellow]Scope is currently empty. "
            "Use 'strixsec scope add <target>' to configure targets.[/yellow]"
        )
        return

    table = Table(title="StrixSec Active Authorization Scope", show_header=True)
    table.add_column("Rule Type", style="bold")
    table.add_column("Target Rule", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Raw Input", style="dim")

    for entry in config.allowed_targets:
        table.add_row("ALLOWED", entry.normalized_target, entry.target_type, entry.raw_target)

    for entry in config.excluded_targets:
        table.add_row("EXCLUDED", entry.normalized_target, entry.target_type, entry.raw_target)

    console.print(table)


@scope_app.command(name="remove")
def remove_scope(
    target: str = typer.Argument(..., help="Target domain, wildcard, IP, or CIDR to remove."),
) -> None:
    """Remove a target entry from the scope configuration."""
    storage = ScopeStorage()
    try:
        removed = storage.remove_target(target)
        if removed:
            console.print(
                f"[bold green][+][/bold green] Scope entry removed: [cyan]{target}[/cyan]"
            )
        else:
            console.print(
                f"[bold yellow][-][/bold yellow] Target '[cyan]{target}[/cyan]' not found in scope."
            )
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] Invalid target format: {err.message}")
        raise typer.Exit(code=1) from err


@scope_app.command(name="validate")
def validate_scope(
    target: str = typer.Argument(
        ..., help="Candidate target to evaluate against authorization scope."
    ),
) -> None:
    """Validate whether a candidate target is explicitly authorized IN SCOPE."""
    storage = ScopeStorage()
    config = storage.load_scope()
    validator = ScopeValidator(config)

    result = validator.validate(target)

    if result.is_in_scope:
        console.print("[bold green][+] Target is IN SCOPE[/bold green]")
        raise typer.Exit(code=0)
    else:
        console.print("[bold red][-] Target is OUT OF SCOPE[/bold red]")
        raise typer.Exit(code=1)
