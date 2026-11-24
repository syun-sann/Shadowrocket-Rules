# Proxy Rules

Personal no-DNS-leak proxy configurations and custom rule sets for **Shadowrocket** and **Mihomo (Clash Meta)**.

## Structure

- `rules/` — Single source of truth for custom rule lists (`ai.list`, `custom-direct.list`, `zoom.list`).
- `shadowrocket/` — Shadowrocket configuration ([nodnsleak.conf](shadowrocket/nodnsleak.conf)).
- `mihomo/` — Mihomo (Clash Meta) configuration template (`nodnsleak.yaml`) and generated rule-providers (`mihomo/rules/`).
- `scripts/` — Conversion and validation tooling (`build_mihomo.py`).

## Privacy Note

This is a public repository. Place any locally filled-in configs containing real subscription URLs in `*.local.yaml` or `*.local.conf` (excluded via `.gitignore`).
