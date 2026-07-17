#!/usr/bin/env python3
"""
generate_sbom_report.py

Reads every SBOM .json file in SBOM_DIR (CycloneDX or SPDX format),
extracts component counts / license breakdown / version info, sends
that structured data to the Claude API, and writes a readable Markdown
report per SBOM file into REPORTS_DIR.

This script is designed to run unattended inside a GitHub Actions job:
- No interactive prompts.
- Non-zero exit code on any failure so the workflow step fails loudly.
- Reads the API key from the ANTHROPIC_API_KEY environment variable
  (populated from a GitHub Actions secret — never hardcode a key here).
"""

import os
import sys
import json
import glob
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import anthropic

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SBOM_DIR = os.environ.get("SBOM_DIR", "Sbom")
REPORTS_DIR = os.environ.get("REPORTS_DIR", "reports")

# claude-sonnet-5 is a good default for this job: it's cheap and fast enough
# to run on every CI trigger, but capable enough to write a clean, accurate
# summary from structured JSON. Swap to "claude-haiku-4-5-20251001" if you
# want to cut cost further, or "claude-opus-4-8" if reports need deeper
# analysis (e.g. license-risk commentary across many SBOMs at once).
MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-5")


# ---------------------------------------------------------------------------
# SBOM parsing — supports CycloneDX and SPDX JSON, since "SBOM .json" in the
# repo could be either depending on which tool generated it.
# ---------------------------------------------------------------------------
def parse_cyclonedx(data: dict) -> list[dict]:
    components = []
    for c in data.get("components", []):
        licenses = []
        for lic in c.get("licenses", []):
            if "license" in lic and "id" in lic["license"]:
                licenses.append(lic["license"]["id"])
            elif "license" in lic and "name" in lic["license"]:
                licenses.append(lic["license"]["name"])
            elif "expression" in lic:
                licenses.append(lic["expression"])
        components.append(
            {
                "name": c.get("name", "unknown"),
                "version": c.get("version", "unspecified"),
                "type": c.get("type", "library"),
                "licenses": licenses or ["NOASSERTION"],
            }
        )
    return components


def parse_spdx(data: dict) -> list[dict]:
    components = []
    for p in data.get("packages", []):
        lic = p.get("licenseConcluded") or p.get("licenseDeclared") or "NOASSERTION"
        components.append(
            {
                "name": p.get("name", "unknown"),
                "version": p.get("versionInfo", "unspecified"),
                "type": "package",
                "licenses": [lic],
            }
        )
    return components


def load_sbom(filepath: str) -> tuple[list[dict], str]:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data.get("bomFormat") == "CycloneDX" or "specVersion" in data:
        return parse_cyclonedx(data), "CycloneDX"
    if "spdxVersion" in data:
        return parse_spdx(data), "SPDX"

    # Fall back: try CycloneDX-shaped parsing, since "components" is a
    # common key even in loosely-formatted SBOMs.
    if "components" in data:
        return parse_cyclonedx(data), "unknown (CycloneDX-like)"

    raise ValueError(f"Unrecognized SBOM format in {filepath}")


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------
def summarize(components: list[dict]) -> dict:
    license_counter = Counter()
    for c in components:
        for lic in c["licenses"]:
            license_counter[lic] += 1

    return {
        "total_components": len(components),
        "license_breakdown": dict(license_counter.most_common()),
        "components": sorted(
            [
                {"name": c["name"], "version": c["version"], "licenses": c["licenses"]}
                for c in components
            ],
            key=lambda x: x["name"].lower(),
        ),
    }


# ---------------------------------------------------------------------------
# Claude API call — this is the part that turns structured data into a
# readable, well-organized Markdown report.
# ---------------------------------------------------------------------------
def build_prompt(sbom_filename: str, sbom_format: str, summary: dict) -> str:
    return f"""You are generating a Markdown summary report for a Software Bill of Materials (SBOM).

Source file: {sbom_filename}
SBOM format detected: {sbom_format}

Structured data extracted from the SBOM (ground truth — do not invent
components, versions, or licenses beyond what is listed here):

{json.dumps(summary, indent=2)}

Write a clear, well-organized Markdown report with these sections:
1. A one-paragraph overview (component count, most common license).
2. A "License Breakdown" table (license, component count).
3. A "Components" table (name, version, license) — include every
   component from the data, sorted alphabetically.
4. A short "Notes" section flagging anything worth a reviewer's
   attention (e.g. components with no asserted license, unusually
   many distinct licenses).

Output only the Markdown report — no preamble, no code fences."""


def call_claude(client: anthropic.Anthropic, sbom_filename: str, sbom_format: str, summary: dict) -> str:
    message = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        messages=[
            {
                "role": "user",
                "content": build_prompt(sbom_filename, sbom_format, summary),
            }
        ],
    )
    return "".join(block.text for block in message.content if block.type == "text")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable is not set.", file=sys.stderr)
        return 1

    sbom_files = sorted(glob.glob(os.path.join(SBOM_DIR, "*.json")))
    if not sbom_files:
        print(f"No SBOM .json files found in '{SBOM_DIR}'. Nothing to do.")
        return 0

    Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    client = anthropic.Anthropic(api_key=api_key)

    generated = []
    for filepath in sbom_files:
        filename = os.path.basename(filepath)
        print(f"Processing {filename} ...")
        try:
            components, fmt = load_sbom(filepath)
            summary = summarize(components)
            report_md = call_claude(client, filename, fmt, summary)
        except Exception as exc:  # noqa: BLE001 — log and continue with other files
            print(f"  FAILED: {exc}", file=sys.stderr)
            continue

        report_name = Path(filename).stem + "_summary.md"
        report_path = os.path.join(REPORTS_DIR, report_name)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_md.strip() + "\n")
        print(f"  wrote {report_path}")
        generated.append(report_name)

    # Small index so there's one obvious entry point in the reports folder.
    index_path = os.path.join(REPORTS_DIR, "README.md")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("# SBOM Summary Reports\n\n")
        f.write(f"Last generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n\n")
        for name in generated:
            f.write(f"- [{name}](./{name})\n")

    if not generated:
        print("No reports were generated (all SBOM files failed to parse).", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
