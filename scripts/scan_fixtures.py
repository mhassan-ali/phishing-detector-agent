"""Scan all email fixtures using the four PhishGuard analyzers (offline, LLM disabled).

Prints a formatted markdown table summarizing findings per fixture.
"""

import sys
from pathlib import Path

from phishguard.analyzers.attachment import AttachmentAnalyzer
from phishguard.analyzers.base import run_analyzer
from phishguard.analyzers.content import ContentAnalyzer
from phishguard.analyzers.header import HeaderAnalyzer
from phishguard.analyzers.url import URLAnalyzer
from phishguard.ingest.extractor import extract_urls
from phishguard.ingest.parser import parse_eml


def main() -> None:
    fixtures_dir = Path("tests/fixtures/emails")
    if not fixtures_dir.exists():
        print(f"Error: Fixtures directory not found: {fixtures_dir}", file=sys.stderr)
        sys.exit(1)

    eml_files = sorted(fixtures_dir.glob("*.eml"))
    if not eml_files:
        print(f"Error: No .eml fixtures found in {fixtures_dir}", file=sys.stderr)
        sys.exit(1)

    analyzers = [
        HeaderAnalyzer(),
        URLAnalyzer(),
        ContentAnalyzer(llm_client=None),
        AttachmentAnalyzer(),
    ]

    print("# PhishGuard Fixture Scan Report (Offline, LLM Disabled)\n")
    print(f"Total fixtures scanned: {len(eml_files)}\n")
    print("| Fixture | Analyzer | Code | Severity | Description |")
    print("|---|---|---|---|---|")

    fixture_counts: dict[str, int] = {}

    for eml_path in eml_files:
        fixture_name = eml_path.name
        data = eml_path.read_bytes()
        parsed = parse_eml(data)
        extract_urls(parsed)

        total_evidence = 0
        for analyzer in analyzers:
            result = run_analyzer(analyzer, parsed)
            for ev in result.evidence:
                total_evidence += 1
                desc_escaped = ev.description.replace("|", "\\|")
                print(
                    f"| `{fixture_name}` | `{ev.source}` | `{ev.code}` "
                    f"| **{ev.severity.value}** | {desc_escaped} |"
                )

        fixture_counts[fixture_name] = total_evidence
        if total_evidence == 0:
            print(f"| `{fixture_name}` | *all* | *(no findings)* | `NONE` | Clean / no triggers |")

    print("\n## Summary of Triggers per Fixture\n")
    for name, count in fixture_counts.items():
        print(f"- `{name}`: {count} evidence item(s)")


if __name__ == "__main__":
    main()
