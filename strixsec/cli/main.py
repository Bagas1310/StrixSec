"""
Main Typer CLI Application Entry Point for StrixSec.
"""

from __future__ import annotations

import platform
import sys

import typer
from rich.console import Console

from strixsec import __version__
from strixsec.cli.assess import assess_app
from strixsec.cli.findings import findings_app
from strixsec.cli.recon import recon_app
from strixsec.cli.report import report_app
from strixsec.cli.scope import scope_app
from strixsec.core.config import get_default_config
from strixsec.core.logging import setup_logger

app = typer.Typer(
    name="strixsec",
    help="StrixSec — Open-Source Cybersecurity Assessment Toolkit",
    add_completion=False,
    no_args_is_help=True,
)

app.add_typer(scope_app, name="scope")
app.add_typer(recon_app, name="recon")
app.add_typer(assess_app, name="assess")
app.add_typer(findings_app, name="findings")
app.add_typer(report_app, name="report")

console = Console()


def version_callback(value: bool) -> None:
    """Callback to handle --version flag directly."""
    if value:
        show_version()
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and system info.",
        callback=version_callback,
        is_eager=True,
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug mode and detailed trace logging.",
    ),
    json_logs: bool = typer.Option(
        False,
        "--json-logs",
        help="Output structured JSON logs to stderr.",
    ),
) -> None:
    """StrixSec global options callback."""
    log_level = "DEBUG" if debug else "INFO"
    setup_logger(level=log_level, json_format=json_logs)


def show_version() -> None:
    """Print version details formatted with rich."""
    config = get_default_config()
    console.print(
        f"[bold cyan]{config.app_name}[/bold cyan] [bold green]v{__version__}[/bold green]"
    )
    console.print(f"Python Runtime: [yellow]{sys.version.split()[0]}[/yellow]")
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    console.print(f"OS Platform:    [yellow]{os_info}[/yellow]")
    console.print("Status:         [bold green]Phase 1 - Project Foundation Ready[/bold green]")


@app.command(name="version")
def version_command() -> None:
    """Display StrixSec version and environment runtime information."""
    show_version()


if __name__ == "__main__":
    app()
