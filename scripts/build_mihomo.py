#!/usr/bin/env python3
"""Convert Shadowrocket rule lists (rules/*.list) into Mihomo classical YAML rule-providers.

Usage:
    python3 scripts/build_mihomo.py          # Generate mihomo/rules/*.yaml and validate
    python3 scripts/build_mihomo.py --check  # Validate only; fail if mihomo/rules/*.yaml is out of sync
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
MIHOMO_RULES_DIR = REPO_ROOT / "mihomo" / "rules"

SUPPORTED_SHADOWROCKET_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP",
    "USER-AGENT",
    "PROCESS-NAME",
    "DST-PORT",
    "SRC-PORT",
    "SRC-IP-CIDR",
}

MIHOMO_UNSUPPORTED_TYPES = {"USER-AGENT"}
NO_RESOLVE_REQUIRED_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}


def convert_list_file(src: Path) -> tuple[str, dict[str, int], list[str]]:
    """Parse a Shadowrocket .list file and return (yaml_content, stats, errors)."""
    errors: list[str] = []
    stats = {
        "total_in": 0,
        "written": 0,
        "dropped_ua": 0,
        "upgraded_ipv6": 0,
        "deduped": 0,
    }
    seen: set[str] = set()
    rules: list[str] = []

    for lineno, raw_line in enumerate(src.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        # Strip inline comments if any
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        parts = [p.strip() for p in line.split(",")]
        rule_type = parts[0].upper()

        if rule_type not in SUPPORTED_SHADOWROCKET_TYPES:
            errors.append(f"{src.name}:{lineno}: unknown rule type '{parts[0]}'")
            continue
        if len(parts) < 2 or not parts[1]:
            errors.append(f"{src.name}:{lineno}: missing rule value in '{line}'")
            continue

        stats["total_in"] += 1

        if rule_type in MIHOMO_UNSUPPORTED_TYPES:
            stats["dropped_ua"] += 1
            continue

        value = parts[1]
        extras = [p.lower() for p in parts[2:] if p]

        # Validate IP/CIDR and auto-upgrade IPv6 tagged as IP-CIDR -> IP-CIDR6
        if rule_type in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                errors.append(f"{src.name}:{lineno}: invalid CIDR '{value}': {exc}")
                continue
            if rule_type == "IP-CIDR" and net.version == 6:
                rule_type = "IP-CIDR6"
                stats["upgraded_ipv6"] += 1
            elif rule_type == "IP-CIDR6" and net.version == 4:
                errors.append(f"{src.name}:{lineno}: IPv4 address tagged as IP-CIDR6: '{value}'")
                continue

        if rule_type == "IP-ASN" and not value.isdigit():
            errors.append(f"{src.name}:{lineno}: invalid ASN '{value}'")
            continue

        if rule_type in NO_RESOLVE_REQUIRED_TYPES and "no-resolve" not in extras:
            errors.append(f"{src.name}:{lineno}: missing 'no-resolve' on {rule_type} rule '{line}'")
            continue

        normalized = ",".join([rule_type, value, *extras])
        if normalized in seen:
            stats["deduped"] += 1
            continue

        seen.add(normalized)
        rules.append(normalized)

    stats["written"] = len(rules)

    header = [
        f"# Auto-generated from rules/{src.name} by scripts/build_mihomo.py",
        "# Do not edit by hand; edit rules/*.list and re-run build_mihomo.py.",
        "payload:",
    ]
    body = [f"  - '{r}'" for r in rules]
    content = "\n".join(header + body) + "\n"
    return content, stats, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and validate Mihomo rule-providers from rules/*.list")
    parser.add_argument("--check", action="store_true", help="Validate without writing; fail if out of sync")
    args = parser.parse_args()

    list_files = sorted(RULES_DIR.glob("*.list"))
    if not list_files:
        print(f"ERROR: no *.list files found in {RULES_DIR}", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    expected_outputs: set[Path] = set()

    if not args.check:
        MIHOMO_RULES_DIR.mkdir(parents=True, exist_ok=True)

    for src in list_files:
        dest = MIHOMO_RULES_DIR / f"{src.stem}.yaml"
        expected_outputs.add(dest)
        content, stats, errors = convert_list_file(src)
        all_errors.extend(errors)

        if errors:
            continue

        if args.check:
            if not dest.exists():
                all_errors.append(f"{dest.relative_to(REPO_ROOT)}: missing generated file (run build_mihomo.py)")
            elif dest.read_text(encoding="utf-8") != content:
                all_errors.append(f"{dest.relative_to(REPO_ROOT)}: out of sync with rules/{src.name} (run build_mihomo.py)")
        else:
            dest.write_text(content, encoding="utf-8")

        print(
            f"{'CHECK' if args.check else 'BUILT'} {dest.relative_to(REPO_ROOT)}: "
            f"{stats['written']} rules "
            f"(in={stats['total_in']}, dropped_ua={stats['dropped_ua']}, "
            f"upgraded_ipv6={stats['upgraded_ipv6']}, deduped={stats['deduped']})"
        )

    # Check for stale generated files in mihomo/rules/
    if MIHOMO_RULES_DIR.exists():
        for existing in sorted(MIHOMO_RULES_DIR.glob("*.yaml")):
            if existing not in expected_outputs:
                all_errors.append(f"{existing.relative_to(REPO_ROOT)}: stale generated file with no matching rules/*.list")

    if all_errors:
        print("\nValidation failed:", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("\nAll rules validated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
