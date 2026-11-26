"""
ChronoNTFS CLI — Three-tier NTFS timestomping detection engine.

Usage:
    python -m chronontfs analyze --mft FILE --usnjrnl FILE --logfile FILE
    python -m chronontfs screen  --mft FILE
    python -m chronontfs filter  --usnjrnl FILE
    python -m chronontfs recover --logfile FILE
"""

import json
import sys
import click
from datetime import datetime, timezone

from .tier1_mft import screen_mft, parse_mft_file
from .tier2_usnjrnl import filter_usnjrnl
from .tier3_logfile import recover_timestamps


def _print_banner():
    click.echo(click.style("""
╔═══════════════════════════════════════════════════════╗
║           ChronoNTFS v0.1.0 — Prototype              ║
║   NTFS Timestomping Detection & Recovery Engine       ║
║   Three-Tier Pipeline: Screen → Filter → Recover      ║
╚═══════════════════════════════════════════════════════╝
    """, fg="cyan"))


@click.group()
def cli():
    """ChronoNTFS: Three-tier NTFS timestomping detection engine."""
    pass


@cli.command()
@click.option("--mft", required=True, type=click.Path(exists=True), help="Path to raw $MFT file")
@click.option("--usnjrnl", required=True, type=click.Path(exists=True), help="Path to raw $UsnJrnl:$J file")
@click.option("--logfile", required=True, type=click.Path(exists=True), help="Path to raw $LogFile")
@click.option("--threshold", default=1.0, type=float, help="Δt threshold in seconds (default: 1.0)")
@click.option("--output", default=None, type=click.Path(), help="Output JSON report path")
def analyze(mft, usnjrnl, logfile, threshold, output):
    """Full three-tier analysis pipeline."""
    _print_banner()

    # ── Tier 1: Screen ──
    click.echo(click.style("\n[Tier 1] Screening $MFT...", fg="blue", bold=True))
    tier1_results = screen_mft(mft)
    click.echo(f"  → {len(tier1_results)} file(s) flagged by MFT rules")

    for r in tier1_results:
        _print_detection(r)

    if not tier1_results:
        click.echo(click.style("\n✓ No anomalies detected. All clean.", fg="green"))
        return

    # Collect flagged FRNs for Tier 2
    flagged_frns = {r.record_number for r in tier1_results}

    # ── Tier 2: Filter ──
    click.echo(click.style("\n[Tier 2] Filtering via $UsnJrnl:$J...", fg="yellow", bold=True))
    tier2_results = filter_usnjrnl(usnjrnl, flagged_frns, threshold)

    benign_count = sum(1 for r in tier2_results if r.classification == "BENIGN_EXTRACTION")
    confirmed_count = sum(1 for r in tier2_results if r.classification == "CONFIRMED_TIMESTOMP")

    click.echo(f"  → {benign_count} benign extraction(s) suppressed (false positive eliminated)")
    click.echo(f"  → {confirmed_count} confirmed timestomping case(s)")

    for r in tier2_results:
        _print_filter(r)

    # Collect confirmed FRNs for Tier 3
    confirmed_frns = {r.frn for r in tier2_results if r.classification == "CONFIRMED_TIMESTOMP"}

    if not confirmed_frns:
        click.echo(click.style("\n✓ All flagged files were benign extractions. No threats.", fg="green"))
        return

    # ── Tier 3: Recover ──
    click.echo(click.style("\n[Tier 3] Recovering timestamps from $LogFile...", fg="magenta", bold=True))
    tier3_results = recover_timestamps(logfile, confirmed_frns)

    click.echo(f"  → {len(tier3_results)} timestamp recovery candidate(s) found")

    for rec in tier3_results:
        click.echo(f"    Original Created:  {rec.original_created_dt}")
        click.echo(f"    Forged Created:    {rec.forged_created_dt}")
        click.echo(f"    Original Modified: {rec.original_modified_dt}")
        click.echo(f"    Forged Modified:   {rec.forged_modified_dt}")
        click.echo()

    # ── Report ──
    if output:
        report = _build_report(tier1_results, tier2_results, tier3_results)
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        click.echo(click.style(f"\n📄 Report saved: {output}", fg="green"))

    click.echo(click.style("\n═══ Analysis complete ═══", fg="cyan", bold=True))


@cli.command()
@click.option("--mft", required=True, type=click.Path(exists=True), help="Path to raw $MFT file")
def screen(mft):
    """Tier 1 only: MFT attribute screening."""
    _print_banner()
    click.echo(click.style("[Tier 1] Screening $MFT...", fg="blue", bold=True))

    results = screen_mft(mft)
    click.echo(f"  → {len(results)} file(s) flagged\n")

    for r in results:
        _print_detection(r)

    if not results:
        click.echo(click.style("✓ No anomalies detected.", fg="green"))


@cli.command()
@click.option("--usnjrnl", required=True, type=click.Path(exists=True), help="Path to raw $UsnJrnl:$J file")
@click.option("--threshold", default=1.0, type=float, help="Δt threshold in seconds")
def filter(usnjrnl, threshold):
    """Tier 2 only: USN Journal event chain filter."""
    _print_banner()
    click.echo(click.style("[Tier 2] Filtering $UsnJrnl:$J...", fg="yellow", bold=True))

    results = filter_usnjrnl(usnjrnl, threshold=threshold)
    for r in results:
        _print_filter(r)


@cli.command()
@click.option("--logfile", required=True, type=click.Path(exists=True), help="Path to raw $LogFile")
def recover(logfile):
    """Tier 3 only: $LogFile timestamp recovery."""
    _print_banner()
    click.echo(click.style("[Tier 3] Recovering from $LogFile...", fg="magenta", bold=True))

    results = recover_timestamps(logfile)
    click.echo(f"  → {len(results)} recovery candidate(s)\n")

    for rec in results:
        click.echo(f"  Original Created:  {rec.original_created_dt}")
        click.echo(f"  Forged Created:    {rec.forged_created_dt}")


# ── Output Helpers ───────────────────────────────────────────────────

def _print_detection(r):
    color = "red" if r.flagged else "green"
    icon = "⚠" if r.flagged else "✓"
    click.echo(click.style(f"  {icon} [{r.record_number}] {r.filename}", fg=color))
    for d in r.details:
        click.echo(f"      {d}")


def _print_filter(r):
    colors = {
        "BENIGN_EXTRACTION": "green",
        "CONFIRMED_TIMESTOMP": "red",
        "UNKNOWN": "yellow",
    }
    icons = {
        "BENIGN_EXTRACTION": "✓",
        "CONFIRMED_TIMESTOMP": "⚠",
        "UNKNOWN": "?",
    }
    color = colors.get(r.classification, "white")
    icon = icons.get(r.classification, "?")

    click.echo(click.style(f"  {icon} [{r.frn}] {r.filename} → {r.classification}", fg=color))
    for d in r.details:
        click.echo(f"      {d}")


def _build_report(tier1, tier2, tier3):
    return {
        "tool": "ChronoNTFS",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tier1_flagged": len(tier1),
        "tier2_benign": sum(1 for r in tier2 if r.classification == "BENIGN_EXTRACTION"),
        "tier2_confirmed": sum(1 for r in tier2 if r.classification == "CONFIRMED_TIMESTOMP"),
        "tier3_recoveries": len(tier3),
        "tier1_details": [
            {"record": r.record_number, "file": r.filename, "rules": r.details}
            for r in tier1
        ],
        "tier2_details": [
            {"frn": r.frn, "file": r.filename, "class": r.classification,
             "delta_t": r.delta_t_finalize, "details": r.details}
            for r in tier2
        ],
    }


if __name__ == "__main__":
    cli()
