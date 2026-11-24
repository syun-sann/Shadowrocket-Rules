# Proxy Rules

Personal no-DNS-leak proxy configurations and custom rule sets for **Shadowrocket** and **Mihomo (Clash Meta)**.

## Structure

- `rules/` — Single source of truth for custom rule lists (`ai.list`, `custom-direct.list`, `zoom.list`).
- `shadowrocket/` — Shadowrocket configuration ([nodnsleak.conf](shadowrocket/nodnsleak.conf)).
- `mihomo/` — Mihomo (Clash Meta) configuration template (`nodnsleak.yaml`) and generated rule-providers (`mihomo/rules/`).
- `scripts/` — Conversion and validation tooling (`build_mihomo.py`).

## Local Usage (Mihomo)

1. Copy `.env.example` to `.env` (gitignored) and set `SUBSCRIPTION_URL`.
2. Run `python3 scripts/build_mihomo.py` after editing `rules/*.list` or `mihomo/nodnsleak.yaml`.
   - Regenerates `mihomo/rules/*.yaml` (committed to GitHub).
   - Auto-generates `mihomo/nodnsleak.local.yaml` with your subscription URL injected (gitignored, ready to import in your Clash/Mihomo client).
