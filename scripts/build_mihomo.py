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
MIHOMO_DIR = REPO_ROOT / "mihomo"
MIHOMO_RULES_DIR = MIHOMO_DIR / "rules"
TEMPLATE_CONFIG = MIHOMO_DIR / "nodnsleak.yaml"
LOCAL_CONFIG = MIHOMO_DIR / "nodnsleak.local.yaml"
ENV_FILE = REPO_ROOT / ".env"
SUBSCRIPTION_PLACEHOLDER = "YOUR_SUBSCRIPTION_URL"

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


def load_dotenv(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE pairs from a .env file without external dependencies."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        env[key] = value
    return env


def check_template_config() -> list[str]:
    """Verify mihomo/nodnsleak.yaml keeps its placeholder URL and avoids known syntax traps."""
    errors: list[str] = []
    if not TEMPLATE_CONFIG.exists():
        return [f"{TEMPLATE_CONFIG.relative_to(REPO_ROOT)}: template config not found"]

    text = TEMPLATE_CONFIG.read_text(encoding="utf-8")
    if SUBSCRIPTION_PLACEHOLDER not in text:
        errors.append(
            f"{TEMPLATE_CONFIG.relative_to(REPO_ROOT)}: missing '{SUBSCRIPTION_PLACEHOLDER}' placeholder "
            "(do not put real subscription URLs in the tracked template; use .env instead)"
        )

    # Guard against removed Mihomo top-level options and nameserver-policy syntax traps
    in_policy = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if raw.startswith("global-client-fingerprint:"):
            errors.append(
                f"{TEMPLATE_CONFIG.relative_to(REPO_ROOT)}:{lineno}: 'global-client-fingerprint' "
                "was removed in Mihomo; set 'client-fingerprint' per proxy or remove it"
            )
        if stripped == "nameserver-policy:":
            in_policy = True
            continue
        if in_policy:
            if raw and not raw.startswith(" ") and not stripped.startswith("#"):
                in_policy = False
            elif stripped.startswith('"') and "," in stripped.split(":", 1)[0]:
                errors.append(
                    f"{TEMPLATE_CONFIG.relative_to(REPO_ROOT)}:{lineno}: comma in nameserver-policy key "
                    f"({stripped.split(':', 1)[0]}); split each geosite/domain into its own key"
                )
    return errors


def render_local_config() -> None:
    """Render gitignored mihomo/nodnsleak.local.yaml using SUBSCRIPTION_URL from .env."""
    env = load_dotenv(ENV_FILE)
    sub_url = env.get("SUBSCRIPTION_URL", "").strip()
    if not sub_url or sub_url == SUBSCRIPTION_PLACEHOLDER:
        print(
            f"SKIP  {LOCAL_CONFIG.relative_to(REPO_ROOT)}: "
            "copy .env.example to .env and set SUBSCRIPTION_URL to auto-generate local config"
        )
        return

    template = TEMPLATE_CONFIG.read_text(encoding="utf-8")
    rendered = template.replace(SUBSCRIPTION_PLACEHOLDER, sub_url)
    banner = "# Auto-generated local config from mihomo/nodnsleak.yaml + .env (gitignored)\n"
    LOCAL_CONFIG.write_text(banner + rendered, encoding="utf-8")
    print(f"BUILT {LOCAL_CONFIG.relative_to(REPO_ROOT)}: injected SUBSCRIPTION_URL from .env")


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

    all_errors.extend(check_template_config())

    if all_errors:
        print("\nValidation failed:", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    if not args.check:
        render_local_config()

    print("\nAll rules and template config validated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
