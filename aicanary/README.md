# AI Data-Leakage Canary System

A defensive security tool for the security team. It plants unique, **entirely
fabricated** "internal facts" into systems the company owns, then watches two
detection points that only fire if a fact escapes the building:

1. an **AWS S3 honeytoken** — each canary references a real, inert S3 object;
   any object-level read alerts.
2. an **outbound public-AI probe** — a scheduled job asks public AI tools
   *around* the fact and fuzzy-matches their answers against the canary's
   unique tokens.

It does not attack or exploit anything. It runs on company-owned
infrastructure and contains only synthetic data.

> This lives alongside the repo's other tool (the browser-based *AI Foundation
> Security Checker* in `index.html` / `README.md`). This document covers the
> Python canary system in `canary/`.

---

## How the trap works

- **Canary** — one fabricated fact (e.g. a fake product codename shipping in
  Q3). Its **codename** and **S3 key** are canary-level unique tokens, shared
  across every variant, so any leak is unambiguously *this* canary.
- **Variants** — the same fact reworded several ways, each issued to a
  different **audience** (team/individual) and carrying its own per-variant
  **marker** (an odd number + a distinctive phrase). This is the *barium-meal*
  trick: the specific wording that leaks tells you the source.
- **Plant** — push the variants into a target surface (Confluence, a local doc
  store, …) an internal AI or person reads from.
- **Detect** — the S3 honeytoken catches direct access to the "further detail"
  object; the public-AI probe catches the fact resurfacing in a third-party
  tool.
- **Correlate** — one dashboard shows, per canary: where/when planted, S3 hits,
  probe hits, and status.

---

## Install

```bash
pip install -r requirements.txt          # core: create / plant / provision / status
pip install -e .                         # optional: installs the `canary` command
# public-AI probe extras (heavy; optional):
pip install -r requirements-probe.txt
python -m playwright install chromium
```

Copy and edit the config:

```bash
cp config/config.example.yaml config/config.yaml
```

Secrets are **never** stored in config — adapters read tokens from environment
variables named in the config (e.g. `CANARY_CONFLUENCE_TOKEN`).

---

## CLI

All commands take `--config` (default `config/config.yaml`) and log to the
central log configured under `storage.log_path`.

```bash
# 1. Generate a canary + variants and create its S3 honeytoken object.
canary create --category product --variants 3 \
    --audience eng-team --audience finance-team
# offline / no AWS:
canary create --category financials --no-honeytoken

# 2. Provision the shared AWS alerting infrastructure (once, then re-run to
#    extend selectors as new honeytoken buckets appear).
canary provision

# 3. Plant a canary's variants into a target surface.
canary plant <canary_id> --target corp_wiki      # Confluence
canary plant <canary_id> --target local_docstore # local reference adapter

# 4. Pull S3 access events from the SQS ingest queue into the local store.
canary ingest

# 5. Run the outbound public-AI probe (ToS-gated; needs --confirm).
canary probe --confirm

# 6. The correlation dashboard.
canary status
canary status <canary_id> --json
```

(Without `pip install -e .`, use `python -m canary ...`.)

---

## The five components

### 1. Canary fact generator — `canary/generator.py`
Category templates live in `config/categories.yaml` (product, financials,
incident, exec_comms, legal). Each canary gets an invented `Project <Codename>`
plus a per-variant odd number and distinctive phrase — statistically unique
tokens that cannot plausibly coincide with real data. Everything is synthetic;
no real product, person, or figure is ever used. Set `generator.seed` for
reproducible generation in tests.

### 2. Internal injection — `canary/injection/`
`plant(canary, variants)` adapter interface with two adapters shipped:

- **`local_docstore`** — reference adapter, writes one Markdown note per
  variant to a directory. No credentials; used by tests and demos.
- **`confluence`** — creates one Confluence page per variant (production
  target). Reads `CANARY_CONFLUENCE_USER` / `CANARY_CONFLUENCE_TOKEN` from the
  environment. Fails loudly (raises on any non-2xx) so a plant that did not
  happen is never recorded.

One document per variant gives a retrieval/embedding index several paraphrases
to match against (higher recall) and keeps each variant traceable to its
audience.

**Adding a target** (RAG ingest endpoint, Slack, tickets, …): subclass
`TargetAdapter`, implement `plant`, decorate with `@register_adapter("name")`,
and add a block under `injection.targets` in config. See
`canary/injection/base.py`.

### 3. AWS S3 honeytoken — `canary/aws/`
- `honeytoken.py` — creates a uniquely-named bucket/key per canary and uploads
  a harmless placeholder PDF. Keys embed the canary_id
  (`<key_prefix>/<canary_id>/<rand>.pdf`) so the Lambda maps a hit back to a
  canary with no lookup table. Buckets get full public-access-block.
- `provision.py` — idempotent boto3 provisioner (choice of IaC: a boto3 setup
  script, to keep one language across the tool). Wires up:
  `honeytoken buckets → CloudTrail data events → EventBridge → Lambda → SNS`.
- `lambda_handler.py` — the deployed function. Extracts timestamp, source IP,
  user agent, bucket/key, maps key → canary_id, and publishes a **structured**
  alert to SNS. **No silent failures**: a missing topic ARN or failed publish
  raises so the miss is visible/retried, never swallowed.
- `ingest.py` — optional consumer that drains an SQS queue (subscribed to the
  SNS topic) into the local store so the dashboard shows S3 hits. It sits
  *beside* the alert path, never on it.

**Alert channel:** SNS topic only. The provisioner creates the topic; attach
your own subscribers:
```bash
aws sns subscribe --topic-arn <arn> --protocol email \
    --notification-endpoint security@example.com
```

**Reuse note (Canarytokens):** Canarytokens' hosted AWS token relies on a
Thinkst-operated CloudTrail; here the security team owns the account and wants
object-level reads on their own keys feeding their own alerting, so we
provision CloudTrail data events + EventBridge directly — small, auditable, no
third-party in the alert path. The Canarytokens *concepts* (unique per-token
IDs, an inert placeholder object) are reused; the control plane is ours.

### 4. Outbound public-AI probe — `canary/probe/`
A scheduled job (`ProbeRunner`) that, per active canary, runs two probe styles
against each enabled tool and fuzzy-matches (`canary/fuzzy.py`, rapidfuzz)
responses against the canary's unique tokens:

- **Inverse/adjacent question** — asks *around* the fact ("what's shipping in
  Q3?"), never feeding the codename or token in.
- **Verbatim-completion extraction test** — membership-inference: give a
  distinctive fragment truncated *before* the unique token and see if the model
  completes it. More directly diagnostic of training-data inclusion, but fails
  silently if the model declines — so both run.

The reference target is **Microsoft Copilot free tier** via Playwright browser
automation.

> ⚠️ **ToS / legal:** Copilot free has no stable, sanctioned API. Driving its
> web UI may violate its Terms of Service. Every run is gated behind
> `--confirm` (and `require_confirmation: true` per tool). Prefer a legitimate
> API for any tool that offers one — add a `ProbeTarget` that calls the API
> instead of a browser.

**Graceful degradation is required:** an unreachable/changed tool logs
"probe failed, tool unreachable" and is skipped; the scheduled run never
crashes. Add tools by subclassing `ProbeTarget` (`canary/probe/base.py`).

### 5. Correlation dashboard — `canary/dashboard.py`
`canary status` renders a plain, dense per-canary report (text or `--json`):
where/when planted, variants + audiences, S3 hits, probe hits, and status.
Clarity over cleverness.

---

## Data model

SQLite (`storage.database_path`) — a single auditable file. Tables: `canaries`,
`variants`, `plants`, `s3_hits`, `probe_hits`. See `canary/store.py` /
`canary/models.py`. Canary status flows `created → planted → triggered`
(a real honeytoken or probe hit flips it to `triggered`).

---

## Scheduling

`canary probe` and `canary ingest` are one-shot and safe to run on a schedule
(cron / systemd timer / EventBridge Scheduler). Example:

```cron
*/15 * * * *  cd /opt/canary && canary ingest            >> /var/log/canary-cron.log 2>&1
0    * * * *  cd /opt/canary && canary probe --confirm   >> /var/log/canary-cron.log 2>&1
```

(Only schedule `probe --confirm` once your security/legal review has cleared
browser automation of the target tools.)

---

## Design constraints honored

- Python + boto3, config-driven (YAML), no hardcoded values.
- Central logging; **no silent failures on the alerting path**.
- **No real company data** anywhere — canary facts and fixtures are fully
  synthetic, always.
- S3 + injection are the solid core; the probe degrades gracefully.

## Roadmap (module slots designed in, not built for v1)

Prompt-injection canary (invisible instruction in docs), honeytoken
credentials (fake keys instrumented like the S3 object), and a DNS canary all
slot into the existing adapter/registry pattern. Per-team/per-individual
variant tracing is already implemented via variant `audience` + `marker`.

## Tests

```bash
pip install pytest
pytest -q
```

Covers the generator, fuzzy matcher, store, local injection adapter, and the
Lambda alerter (SNS mocked). AWS provisioning and the Playwright probe are not
exercised against live services in unit tests.
