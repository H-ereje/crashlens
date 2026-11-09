import sys
import os
from pathlib import Path
from typing import Optional

from ..core.parser import LogParser
from ..core.aggregator import IncidentAggregator
from ..core.models import Severity
from ..ai.engine import DiagnosticEngine
from ..export.html_report import HTMLReportGenerator

# Ensure standard UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Check for rich for styled terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.progress import Progress, SpinnerColumn, TextColumn
    HAS_RICH = True
    console = Console(force_terminal=True, legacy_windows=False)
except ImportError:
    HAS_RICH = False
    console = None


def print_banner():
    banner = r"""
   ______               __    __                     
  / ____/________ _____/ /_  / /   ___  ____  _____   
 / /   / ___/ __ `/ ___/ __ \/ /   / _ \/ __ \/ ___/   
/ /___/ /  / /_/ (__  ) / / / /___/  __/ / / (__  )    
\____/_/   \__,_/____/_/ /_/_____/\___/_/ /_/____/     
    >> Automated Log Fingerprinting & AI Incident Triage Engine <<
"""
    if HAS_RICH:
        console.print(f"[bold cyan]{banner}[/bold cyan]")
    else:
        print(banner)


def cmd_scan(file_path: Path, min_severity: str = "WARNING"):
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    print_banner()

    aggregator = IncidentAggregator(min_severity=Severity.from_str(min_severity))

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        aggregator.ingest(LogParser.parse_stream(f))

    incidents = aggregator.get_incidents(sort_by="count")
    stats = aggregator.stats

    if HAS_RICH:
        table = Table(
            title=f"Incident Analysis: {file_path.name}",
            border_style="cyan",
            header_style="bold magenta",
        )
        table.add_column("Fingerprint", style="bold cyan", justify="center")
        table.add_column("Severity", justify="center")
        table.add_column("Count", justify="center", style="bold yellow")
        table.add_column("Incident Title / Root Error", justify="left")
        table.add_column("Source", style="dim", justify="left")

        for inc in incidents:
            sev_color = {
                Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
                Severity.ERROR: "[red]ERROR[/red]",
                Severity.WARNING: "[yellow]WARN[/yellow]",
            }.get(inc.severity, "[white]INFO[/white]")

            loc = f"{Path(inc.affected_file).name}:{inc.affected_line}" if inc.affected_file else "-"
            table.add_row(
                inc.fingerprint,
                sev_color,
                f"x{inc.count}",
                inc.title[:75],
                loc,
            )

        console.print(table)

        # Compression ratio
        raw_errs = stats["total_issues_found"]
        uniq = stats["unique_incidents"]
        reduction = ((raw_errs - uniq) / raw_errs * 100) if raw_errs > 0 else 0

        summary = (
            f"[bold green][OK] Analysis Complete:[/bold green] Scanned [cyan]{stats['total_lines']}[/cyan] lines | "
            f"Clustered [red]{raw_errs}[/red] errors into [yellow]{uniq}[/yellow] unique incidents "
            f"([bold cyan]{reduction:.1f}% noise reduction[/bold cyan])."
        )
        console.print(Panel(summary, border_style="green"))
        console.print("\n[dim]Tip: Run [bold white]crashlens diagnose <file> <fingerprint>[/bold white] to generate an AI root-cause patch.[/dim]\n")
    else:
        print(f"\nAnalysis for: {file_path.name}")
        print("-" * 80)
        print(f"{'FINGERPRINT':<14} {'SEVERITY':<10} {'COUNT':<8} {'TITLE'}")
        print("-" * 80)
        for inc in incidents:
            print(f"{inc.fingerprint:<14} {inc.severity.value:<10} x{inc.count:<7} {inc.title[:50]}")
        print("-" * 80)
        print(f"Total lines: {stats['total_lines']} | Errors: {stats['total_issues_found']} | Incidents: {stats['unique_incidents']}")


def cmd_diagnose(file_path: Path, target_fingerprint: str, api_key: Optional[str] = None):
    print_banner()

    aggregator = IncidentAggregator(min_severity=Severity.DEBUG)
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        aggregator.ingest(LogParser.parse_stream(f))

    target = aggregator.incidents.get(target_fingerprint.upper())
    if not target:
        # Search partial match
        matches = [inc for fp, inc in aggregator.incidents.items() if target_fingerprint.upper() in fp]
        if matches:
            target = matches[0]

    if not target:
        print(f"Error: Fingerprint '{target_fingerprint}' not found in {file_path.name}")
        sys.exit(1)

    engine = DiagnosticEngine(api_key=api_key)
    diagnosis = engine.diagnose(target)

    if HAS_RICH:
        console.print(f"[bold cyan]Diagnosing Incident #[/bold cyan][bold yellow]{target.fingerprint}[/bold yellow]: [white]{target.title}[/white]\n")
        
        # Root cause panel
        console.print(Panel(
            diagnosis.get("root_cause", ""),
            title="[bold red]1. Root Cause Analysis[/bold red]",
            border_style="red"
        ))

        # Recommendations panel
        console.print(Panel(
            diagnosis.get("recommendation", ""),
            title="[bold yellow]2. Actionable Remediation[/bold yellow]",
            border_style="yellow"
        ))

        # Code patch
        patch_text = diagnosis.get("code_patch", "")
        if patch_text:
            clean_patch = patch_text.replace("```diff\n", "").replace("```", "")
            console.print(Panel(
                Syntax(clean_patch, "diff", theme="monokai", line_numbers=False),
                title="[bold green]3. Suggested Code Patch (Git Diff)[/bold green]",
                border_style="green"
            ))
    else:
        print(f"\n=== DIAGNOSIS FOR INCIDENT #{target.fingerprint} ===")
        print(f"Title: {target.title}\n")
        print(f"[ROOT CAUSE]\n{diagnosis.get('root_cause')}\n")
        print(f"[RECOMMENDATIONS]\n{diagnosis.get('recommendation')}\n")
        print(f"[PATCH]\n{diagnosis.get('code_patch')}\n")


def cmd_report(file_path: Path, output_path: Path):
    aggregator = IncidentAggregator(min_severity=Severity.DEBUG)
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        aggregator.ingest(LogParser.parse_stream(f))

    incidents = aggregator.get_incidents(sort_by="count")
    engine = DiagnosticEngine()

    # Enrich top 5 incidents with diagnosis
    for inc in incidents[:5]:
        diag = engine.diagnose(inc)
        inc.ai_diagnosis = f"{diag.get('root_cause')}\n\nRecommended Fix:\n{diag.get('recommendation')}"

    html_content = HTMLReportGenerator.generate(incidents, aggregator.stats, title=f"CrashLens Report: {file_path.name}")

    with open(output_path, "w", encoding="utf-8") as out:
        out.write(html_content)

    if HAS_RICH:
        console.print(f"[bold green][OK] Interactive HTML Report generated:[/bold green] [cyan]{output_path.resolve()}[/cyan]")
    else:
        print(f"Report generated: {output_path.resolve()}")


def cmd_demo():
    """Generates synthetic real-world incident logs and runs an automated scan."""
    sample_dir = Path(__file__).parent.parent.parent / "sample_logs"
    sample_dir.mkdir(exist_ok=True, parents=True)
    sample_file = sample_dir / "microservices_production.log"

    # Create realistic sample logs if not exist
    if not sample_file.exists():
        create_sample_logs(sample_file)

    cmd_scan(sample_file)


def create_sample_logs(target_path: Path):
    content = """2026-11-09 10:14:02.120 [INFO] app.server: Starting worker thread pid=4124
2026-11-09 10:14:05.340 [ERROR] app.database: OperationalError: connection to server at "10.0.4.12", port 5432 failed: Connection refused
Traceback (most recent call last):
  File "app/database/connection.py", line 42, in get_connection
    conn = psycopg2.connect(dsn, connect_timeout=3)
  File "psycopg2/__init__.py", line 122, in connect
    return _connect(dsn, connection_factory=connection_factory, **kwasync)
psycopg2.OperationalError: connection to server at "10.0.4.12", port 5432 failed: Connection refused
2026-11-09 10:14:06.110 [ERROR] app.database: OperationalError: connection to server at "10.0.4.12", port 5432 failed: Connection refused
Traceback (most recent call last):
  File "app/database/connection.py", line 42, in get_connection
    conn = psycopg2.connect(dsn, connect_timeout=3)
psycopg2.OperationalError: connection to server at "10.0.4.12", port 5432 failed: Connection refused
2026-11-09 10:14:07.890 [ERROR] app.services.users: AttributeError: 'NoneType' object has no attribute 'email'
Traceback (most recent call last):
  File "app/services/users.py", line 87, in send_welcome_email
    recipient = user.email.lower()
AttributeError: 'NoneType' object has no attribute 'email'
2026-11-09 10:14:09.112 [ERROR] app.database: OperationalError: connection to server at "10.0.4.12", port 5432 failed: Connection refused
Traceback (most recent call last):
  File "app/database/connection.py", line 42, in get_connection
    conn = psycopg2.connect(dsn, connect_timeout=3)
psycopg2.OperationalError: connection to server at "10.0.4.12", port 5432 failed: Connection refused
2026-11-09 10:14:12.300 [ERROR] app.services.users: AttributeError: 'NoneType' object has no attribute 'email'
Traceback (most recent call last):
  File "app/services/users.py", line 87, in send_welcome_email
    recipient = user.email.lower()
AttributeError: 'NoneType' object has no attribute 'email'
2026-11-09 10:14:15.540 [WARN] app.cache: Redis connection timeout to redis-cache.cluster:6379 after 2000ms
2026-11-09 10:14:18.210 [ERROR] app.api.auth: KeyError: 'auth_token'
Traceback (most recent call last):
  File "app/api/auth.py", line 34, in verify_request
    token = payload['auth_token']
KeyError: 'auth_token'
"""
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="CrashLens: AI-Powered Terminal Log & Incident Triage Engine",
        prog="crashlens"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan log file and cluster incidents")
    p_scan.add_argument("file", type=Path, help="Path to log file")
    p_scan.add_argument("--min-severity", default="WARNING", help="Minimum severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")

    # diagnose
    p_diag = subparsers.add_parser("diagnose", help="AI Root-Cause Diagnosis and Code Patch")
    p_diag.add_argument("file", type=Path, help="Path to log file")
    p_diag.add_argument("fingerprint", type=str, help="Incident fingerprint hash")
    p_diag.add_argument("--key", type=str, default=None, help="Gemini or OpenAI API key (optional)")

    # report
    p_rep = subparsers.add_parser("report", help="Generate an interactive HTML report")
    p_rep.add_argument("file", type=Path, help="Path to log file")
    p_rep.add_argument("--output", "-o", type=Path, default=Path("crashlens_report.html"), help="Output HTML file path")

    # demo
    subparsers.add_parser("demo", help="Generate sample logs and demonstrate live analysis")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args.file, args.min_severity)
    elif args.command == "diagnose":
        cmd_diagnose(args.file, args.fingerprint, args.key)
    elif args.command == "report":
        cmd_report(args.file, args.output)
    elif args.command == "demo":
        cmd_demo()


if __name__ == "__main__":
    main()
