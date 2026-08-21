"""
CLI subcommand for Phase 6 reporting.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from strixsec.reporting.builder import ReportBuilder
from strixsec.reporting.html_renderer import render_html
from strixsec.reporting.markdown_renderer import render_markdown

report_app = typer.Typer(help="Generate security assessment reports.")
console = Console()


@report_app.command(name="generate")
def generate(
    output: Path = typer.Option(
        Path("report.md"),
        "--output",
        "-o",
        help="Output file path.",
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report format: markdown or html.",
    ),
    title: str = typer.Option(
        "StrixSec Security Assessment Report",
        "--title",
        "-t",
        help="Report title.",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter findings by severity.",
    ),
    status: str | None = typer.Option(
        None,
        "--status",
        help="Filter findings by status.",
    ),
) -> None:
    """Generate a security assessment report from stored findings."""
    builder = ReportBuilder()
    ctx = builder.build(title=title, severity_filter=severity, status_filter=status)

    content = render_html(ctx) if format.lower() == "html" else render_markdown(ctx)

    output.write_text(content, encoding="utf-8")
    console.print(f"[green]OK[/green] Report written to {output}")
