"""
CLI Subcommands for StrixSec Security Assessment Subsystem.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from strixsec.assessment.engine import AssessmentEngine
from strixsec.assessment.models import AssessmentResult
from strixsec.core.errors import ScopeValidationError, StrixSecError
from strixsec.findings import generate_findings_from_assessment
from strixsec.storage.database import DatabaseManager

assess_app = typer.Typer(
    name="assess",
    help="Perform safe non-destructive security assessment (Headers, TLS, Cookies, Metadata).",
    no_args_is_help=True,
)

console = Console()


def _store_assessment_findings(result: AssessmentResult) -> int:
    """Convert AssessmentResult into Finding models and persist them to SQLite.

    Reuses the existing findings generator and database manager so that
    deduplication (asset + category + title) applies on re-runs.

    Args:
        result: Any AssessmentResult (full suite or partial from a single module).

    Returns:
        Number of findings stored or updated.
    """
    db = DatabaseManager()
    findings = generate_findings_from_assessment(result)
    if not findings:
        console.print("[yellow]- No findings to persist.[/yellow]")
        return 0
    for finding in findings:
        saved = db.save_finding(finding)
        console.print(f"[green]+[/green] Finding stored: [cyan]{saved.id}[/cyan] — {saved.title}")
    return len(findings)


@assess_app.command(name="headers")
def assess_headers(
    target: str = typer.Argument(..., help="Authorized target domain, IP, or URL."),
) -> None:
    """Assess HTTP response security headers for authorized target."""
    engine = AssessmentEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] Security header assessment started...")

        result = engine.run_headers(target)

        table = Table(title=f"Security Headers for {norm_target}", show_header=True)
        table.add_column("Header Name", style="bold")
        table.add_column("Status", style="magenta")
        table.add_column("Value / Guidance", style="cyan")

        for check in result.checks:
            status_str = (
                "[bold green]PRESENT[/bold green]"
                if check.is_present
                else "[bold yellow]MISSING[/bold yellow]"
            )
            val_str = check.value if check.is_present else check.recommendation
            table.add_row(check.header_name, status_str, val_str)

        console.print(table)
        _store_assessment_findings(AssessmentResult(target=norm_target, headers_result=result))
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Assessment error: {err.message}")
        raise typer.Exit(code=1) from err


@assess_app.command(name="tls")
def assess_tls(
    target: str = typer.Argument(..., help="Authorized target domain or IP."),
    port: int = typer.Option(443, "--port", "-p", help="TLS port number."),
) -> None:
    """Inspect TLS certificate and protocol configuration for authorized target."""
    engine = AssessmentEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print(f"[bold cyan][+][/bold cyan] TLS inspection started on port {port}...")

        tls_res = engine.run_tls(target, port=port)

        if tls_res.error:
            console.print(f"[bold yellow][-][/bold yellow] TLS Assessment Notice: {tls_res.error}")

        table = Table(title=f"TLS Assessment for {norm_target}:{port}", show_header=True)
        table.add_column("Attribute", style="bold")
        table.add_column("Value", style="cyan")

        table.add_row("Status", tls_res.status)
        table.add_row("TLS Version", tls_res.tls_version or "N/A")

        if tls_res.cert_info:
            c = tls_res.cert_info
            table.add_row("Subject CN", c.subject.get("commonName", "N/A"))
            table.add_row("Issuer O", c.issuer.get("organizationName", "N/A"))
            table.add_row("Valid From", c.valid_from)
            table.add_row("Valid To", c.valid_to)
            table.add_row("Days Remaining", str(c.days_until_expiration))
            table.add_row("Expired", "[red]YES[/red]" if c.is_expired else "[green]NO[/green]")
            table.add_row(
                "Hostname Matches", "[green]YES[/green]" if c.hostname_matches else "[red]NO[/red]"
            )
            table.add_row("SANs Count", str(len(c.sans)))

        console.print(table)
        _store_assessment_findings(AssessmentResult(target=norm_target, tls_result=tls_res))
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Assessment error: {err.message}")
        raise typer.Exit(code=1) from err


@assess_app.command(name="cookies")
def assess_cookies(
    target: str = typer.Argument(..., help="Authorized target domain, IP, or URL."),
) -> None:
    """Analyze Set-Cookie security flags with mandatory value redaction."""
    engine = AssessmentEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] Cookie security assessment started...")

        cookie_res = engine.run_cookies(target)

        if not cookie_res.cookies:
            console.print("[yellow]No Set-Cookie headers were observed in the response.[/yellow]")
            return

        table = Table(title=f"Cookie Security Analysis for {norm_target}", show_header=True)
        table.add_column("Cookie Name", style="bold")
        table.add_column("Secure", style="magenta")
        table.add_column("HttpOnly", style="yellow")
        table.add_column("SameSite", style="cyan")
        table.add_column("Redacted Set-Cookie Header", style="dim")

        for c in cookie_res.cookies:
            sec_str = "[green]YES[/green]" if c.secure else "[red]NO[/red]"
            http_str = "[green]YES[/green]" if c.httponly else "[red]NO[/red]"
            ss_str = c.samesite or "[yellow]Missing[/yellow]"
            table.add_row(c.cookie_name, sec_str, http_str, ss_str, c.redacted_header)

        console.print(table)
        _store_assessment_findings(AssessmentResult(target=norm_target, cookie_result=cookie_res))
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Assessment error: {err.message}")
        raise typer.Exit(code=1) from err


@assess_app.command(name="metadata")
def assess_metadata(
    target: str = typer.Argument(..., help="Authorized target domain, IP, or URL."),
) -> None:
    """Inspect safe public security metadata files (robots.txt, security.txt)."""
    engine = AssessmentEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] Public metadata assessment started...")

        meta_res = engine.run_metadata(target)

        table = Table(title=f"Public Security Metadata for {norm_target}", show_header=True)
        table.add_column("Metadata Resource", style="bold")
        table.add_column("Status", style="magenta")
        table.add_column("Snippet Preview", style="dim")

        rob_status = (
            "[green]FOUND[/green]" if meta_res.robots_found else "[yellow]NOT FOUND[/yellow]"
        )
        rob_snip = (meta_res.robots_content[:80] + "...") if meta_res.robots_content else "N/A"
        table.add_row("robots.txt", rob_status, rob_snip)

        sec_status = (
            "[green]FOUND[/green]" if meta_res.security_txt_found else "[yellow]NOT FOUND[/yellow]"
        )
        sec_snip = (
            (meta_res.security_txt_content[:80] + "...") if meta_res.security_txt_content else "N/A"
        )
        table.add_row("security.txt", sec_status, sec_snip)

        console.print(table)
        _store_assessment_findings(AssessmentResult(target=norm_target, metadata_result=meta_res))
    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Assessment error: {err.message}")
        raise typer.Exit(code=1) from err


@assess_app.command(name="all")
def assess_all(
    target: str = typer.Argument(..., help="Authorized target domain, IP, or URL."),
) -> None:
    """Run complete safe security assessment suite for authorized target."""
    engine = AssessmentEngine()
    try:
        norm_target = engine.validate_and_normalize(target)
        console.print(f"[bold green][+][/bold green] Target validated: [cyan]{norm_target}[/cyan]")
        console.print("[bold cyan][+][/bold cyan] Full security assessment suite started...")

        res = engine.run_full_assessment(target)

        console.print(f"[bold green]Security Assessment completed for {res.target}[/bold green]")
        if res.headers_result:
            present_cnt = sum(1 for c in res.headers_result.checks if c.is_present)
            console.print(
                f"  - Security Headers: {present_cnt}/{len(res.headers_result.checks)} present"
            )
        if res.tls_result:
            console.print(
                f"  - TLS Status: {res.tls_result.status} "
                f"(Version: {res.tls_result.tls_version or 'N/A'})"
            )
        if res.cookie_result:
            console.print(
                f"  - Evaluated Cookies: {len(res.cookie_result.cookies)} (Values REDACTED)"
            )
        if res.metadata_result:
            console.print(
                f"  - Public Metadata: robots.txt ({res.metadata_result.robots_found}), "
                f"security.txt ({res.metadata_result.security_txt_found})"
            )

        _store_assessment_findings(res)

    except ScopeValidationError as err:
        console.print(f"[bold red][-][/bold red] {err.message}")
        console.print("[bold red][-][/bold red] Network operation blocked.")
        raise typer.Exit(code=1) from err
    except StrixSecError as err:
        console.print(f"[bold red][-][/bold red] Assessment error: {err.message}")
        raise typer.Exit(code=1) from err
