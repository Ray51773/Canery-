"""Command-line interface.

    canary create   - generate a fabricated canary + variants, create its S3
                      honeytoken object, store it.
    canary plant    - push a canary's variants into a target surface.
    canary provision- provision the shared AWS alerting infrastructure.
    canary ingest   - pull S3 access events from the SQS queue into the store.
    canary probe    - run the outbound public-AI probe (confirmation-gated).
    canary status   - the correlation dashboard.

All commands are config-driven (``--config``, default config/config.yaml) and
log to the central log.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import __version__
from .config import Config, ConfigError, load_config
from .dashboard import build_report, render_json, render_text
from .generator import CanaryGenerator, rewrite_s3_url
from .logging_setup import setup_logging
from .models import INTENT_DETECT, INTENT_DETER, STATUS_PLANTED
from .store import Store


def _bootstrap(args) -> tuple[Config, Store]:
    config = load_config(args.config)
    setup_logging(config.log_path, config.log_level)
    store = Store(config.database_path)
    return config, store


# --- create --------------------------------------------------------------
def _parse_validations(raw_entries: list[str]) -> list[dict]:
    """Parse repeated --validated 'model=..,version=..,date=..,result=..'
    strings into last_validated_against dicts."""
    out = []
    for entry in raw_entries or []:
        rec = {"model": "", "version": "", "date": "", "result": "refused"}
        for part in entry.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.strip()
                if k in rec:
                    rec[k] = v.strip()
        if rec["model"] and rec["date"]:
            out.append(rec)
    return out


def cmd_create(args) -> int:
    if getattr(args, "intent", INTENT_DETECT) == INTENT_DETER:
        return _cmd_create_deter(args)
    return _cmd_create_detect(args)


def _cmd_create_deter(args) -> int:
    """Create a context bomb (intent=deter): the user-supplied payload becomes
    the value of a real decoy Secrets Manager secret, whose read alerts on the
    same SNS path as an S3 honeytoken. No fabricated fact is generated."""
    config, store = _bootstrap(args)
    gen = CanaryGenerator.from_file(
        config.generator.get("categories_file", "config/categories.yaml"),
        seed=config.generator.get("seed"),
    )
    # Payload from a file (preferred - keeps it out of shell history) or inline.
    payload = args.payload
    if args.payload_file:
        try:
            with open(args.payload_file, "r", encoding="utf-8") as fh:
                payload = fh.read().strip()
        except OSError as exc:
            print(f"ERROR reading --payload-file: {exc}", file=sys.stderr)
            return 1
    if not payload:
        print("A deter artefact needs a payload. Pass --payload-file <path> "
              "(preferred) or --payload <string>.", file=sys.stderr)
        return 1

    validations = _parse_validations(args.validated)
    if not validations and not args.unvalidated:
        print("Refusing to save an unvalidated bomb by default. Record what you "
              "tested it against with --validated 'model=..,date=..,result=..' "
              "(repeatable), or pass --unvalidated to save it explicitly flagged.",
              file=sys.stderr)
        return 1

    shape = args.shape or "secrets_manager"
    canary, variants = gen.generate_deter(
        payload=payload, shape=shape, assets=args.asset or [],
        n_variants=(args.variants or len(args.asset or []) or 3),
        payload_source=args.payload_source, guardrail_dependency=args.guardrail or "",
        validations=validations, label=args.label,
    )

    if not args.no_honeytoken:
        try:
            from .aws.honeytoken import SecretHoneytokenManager
            mgr = SecretHoneytokenManager(config.aws)
            secret = mgr.create_secret(canary.canary_id, payload, shape=shape)
            # Swap the real resource back into the artefact record so the
            # console export and the alert path agree on the ARN.
            canary.s3_key = secret["name"]
            canary.s3_url = secret["arn"]
        except Exception as exc:
            print(f"ERROR creating decoy secret: {exc}", file=sys.stderr)
            print("  (use --no-honeytoken to record a bomb without creating the "
                  "real secret, e.g. offline)", file=sys.stderr)
            return 2

    store.add_canary(canary)
    for v in variants:
        store.add_variant(v)

    print(f"Created context bomb {canary.canary_id}")
    print(f"  shape        : {shape}")
    print(f"  payload src  : {canary.payload_source}")
    print(f"  guardrail    : {canary.guardrail_dependency or '(not recorded)'}")
    print(f"  secret ref   : {canary.s3_url or '(no secret created)'}")
    print(f"  assets       : {len(variants)}")
    print(f"  validated    : {len(validations)} entr(y/ies)"
          + ("  [UNVALIDATED]" if not validations else ""))
    for v in variants:
        print(f"    - {v.variant_id}  asset='{v.audience}'")
    return 0


def _cmd_create_detect(args) -> int:
    config, store = _bootstrap(args)
    gen = CanaryGenerator.from_file(
        config.generator.get("categories_file", "config/categories.yaml"),
        seed=config.generator.get("seed"),
    )
    category = args.category or config.generator.get("default_category", "product")
    n = args.variants or int(config.generator.get("variants_per_canary", 3))
    audiences = args.audience or []

    canary, variants = gen.generate(category, n_variants=n, audiences=audiences)

    # Create the S3 honeytoken object unless suppressed (offline/dry runs).
    if not args.no_honeytoken:
        try:
            from .aws.honeytoken import HoneytokenManager
            mgr = HoneytokenManager(config.aws)
            shared_bucket = args.bucket
            obj = mgr.create_object(canary.canary_id, bucket_name=shared_bucket)
            canary.s3_bucket = obj["bucket"]
            canary.s3_key = obj["key"]
            canary.s3_url = obj["url"]
            # Rewrite the pending sentinel in the fact text now the URL exists.
            canary.base_fact = rewrite_s3_url(canary.base_fact, obj["url"])
            for v in variants:
                v.text = rewrite_s3_url(v.text, obj["url"])
        except Exception as exc:
            print(f"ERROR creating S3 honeytoken: {exc}", file=sys.stderr)
            print("  (use --no-honeytoken to create a canary without S3, e.g. offline)",
                  file=sys.stderr)
            return 2

    store.add_canary(canary)
    for v in variants:
        store.add_variant(v)

    print(f"Created canary {canary.canary_id}")
    print(f"  category : {canary.category}")
    print(f"  codename : {canary.codename}")
    print(f"  s3 ref   : {canary.s3_url}")
    print(f"  variants : {len(variants)}")
    for v in variants:
        print(f"    - {v.variant_id}  audience='{v.audience}'")
        print(f"        {v.text}")
    return 0


# --- plant ---------------------------------------------------------------
def cmd_plant(args) -> int:
    config, store = _bootstrap(args)
    canary = store.get_canary(args.canary_id)
    if canary is None:
        print(f"No such canary: {args.canary_id}", file=sys.stderr)
        return 1
    variants = store.list_variants(canary.canary_id)
    if not variants:
        print(f"Canary {canary.canary_id} has no variants", file=sys.stderr)
        return 1

    from .injection import get_adapter

    target_block = config.injection_target(args.target)
    adapter_cls = get_adapter(target_block["adapter"])
    adapter = adapter_cls(target_block, config)

    try:
        results = adapter.plant(canary, variants)
    except Exception as exc:
        print(f"ERROR planting into {target_block['name']}: {exc}", file=sys.stderr)
        return 2

    plants = adapter.to_plants(canary, results)
    for p in plants:
        store.add_plant(p)
    store.set_canary_status(canary.canary_id, STATUS_PLANTED)

    print(f"Planted canary {canary.canary_id} into '{adapter.target_system}':")
    for p in plants:
        print(f"  - {p.variant_id} -> {p.location}")
    return 0


# --- provision -----------------------------------------------------------
def cmd_provision(args) -> int:
    config, store = _bootstrap(args)
    from .aws.provision import Provisioner

    # Collect honeytoken buckets from existing canaries so their reads alert.
    buckets = sorted({
        c.s3_bucket for c in store.list_canaries() if c.s3_bucket
    })
    if args.bucket:
        buckets = sorted(set(buckets) | set(args.bucket))
    if not buckets:
        print("No honeytoken buckets known yet. Create a canary first, or pass "
              "--bucket <name>. Provisioning shared infra without a bucket "
              "selector would alert on ALL S3 reads.", file=sys.stderr)
        if not args.allow_empty:
            return 1

    prov = Provisioner(config.aws)
    try:
        out = prov.provision_all(buckets)
    except Exception as exc:
        print(f"ERROR provisioning: {exc}", file=sys.stderr)
        return 2
    print("Provisioned AWS alerting infrastructure:")
    for k, v in out.items():
        print(f"  {k}: {v}")
    print("\nAttach subscribers to the SNS topic to receive alerts, e.g.:")
    print(f"  aws sns subscribe --topic-arn {out['sns_topic_arn']} "
          f"--protocol email --notification-endpoint you@example.com")
    return 0


# --- ingest --------------------------------------------------------------
def cmd_ingest(args) -> int:
    config, store = _bootstrap(args)
    from .aws.ingest import HitIngestor

    if not config.aws.get("ingest_queue_name"):
        print("No ingest_queue_name configured; nothing to ingest.", file=sys.stderr)
        return 1
    ing = HitIngestor(config.aws, store)
    try:
        n = ing.ingest_once()
    except Exception as exc:
        print(f"ERROR ingesting hits: {exc}", file=sys.stderr)
        return 2
    print(f"Ingested {n} new honeytoken read hit(s) (S3 + Secrets Manager).")
    return 0


# --- probe ---------------------------------------------------------------
def cmd_probe(args) -> int:
    config, store = _bootstrap(args)
    from .probe.runner import ProbeRunner

    gen = CanaryGenerator.from_file(
        config.generator.get("categories_file", "config/categories.yaml"),
        seed=config.generator.get("seed"),
    )
    if not args.confirm:
        print("Public-AI probing drives third-party web UIs (ToS risk) and is "
              "gated. Re-run with --confirm to actually run enabled tools.",
              file=sys.stderr)
    # Probing a deter bomb is meaningless (a bomb succeeds by making a model
    # refuse) and would put the payload into a public tool - the runner skips
    # deter artefacts entirely.
    runner = ProbeRunner(config, store, gen, confirmed=args.confirm)
    summary = runner.run()
    print("Probe run summary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    return 0


# --- status --------------------------------------------------------------
def cmd_status(args) -> int:
    config, store = _bootstrap(args)
    report = build_report(store, canary_id=args.canary_id)
    if args.json:
        print(render_json(report))
    else:
        print(render_text(report), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="canary",
        description="AI Data-Leakage Canary System - defensive security tool.",
    )
    p.add_argument("--version", action="version", version=f"canary {__version__}")
    p.add_argument("--config", default="config/config.yaml",
                   help="path to config YAML (default: config/config.yaml)")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("create", help="generate a canary (detect) or context bomb (deter)")
    c.add_argument("--intent", choices=[INTENT_DETECT, INTENT_DETER], default=INTENT_DETECT,
                   help="detect = tracer canary (default); deter = context bomb")
    c.add_argument("--variants", type=int, help="number of variants / assets")
    c.add_argument("--no-honeytoken", action="store_true",
                   help="skip real AWS resource creation (offline/dry run)")
    # detect (tracer) options
    c.add_argument("--category", help="[detect] fact category (default from config)")
    c.add_argument("--audience", action="append",
                   help="[detect] audience/team tag for a variant (repeatable, in order)")
    c.add_argument("--bucket", help="[detect] reuse a specific honeytoken bucket")
    # deter (context bomb) options
    c.add_argument("--shape", help="[deter] decoy resource shape (secrets_manager, env, "
                   "aws_credentials, dns_txt, iam_role)")
    c.add_argument("--payload", help="[deter] payload string (prefer --payload-file)")
    c.add_argument("--payload-file", help="[deter] file holding the payload (keeps it "
                   "out of shell history)")
    c.add_argument("--asset", action="append",
                   help="[deter] decoy asset name for a variant (repeatable, in order)")
    c.add_argument("--label", help="[deter] human label for the bomb")
    c.add_argument("--guardrail", help="[deter] vendor safety behaviour the payload relies on")
    c.add_argument("--payload-source", choices=["user_supplied", "builtin_reference"],
                   default="user_supplied", help="[deter] payload provenance")
    c.add_argument("--validated", action="append", default=[],
                   help="[deter] validation entry 'model=..,version=..,date=..,result=..' "
                   "(repeatable). Required unless --unvalidated.")
    c.add_argument("--unvalidated", action="store_true",
                   help="[deter] save with no validation, explicitly flagged")
    c.set_defaults(func=cmd_create)

    pl = sub.add_parser("plant", help="push a canary's variants into a target surface")
    pl.add_argument("canary_id")
    pl.add_argument("--target", help="injection target name (default from config)")
    pl.set_defaults(func=cmd_plant)

    pv = sub.add_parser("provision", help="provision AWS alerting infrastructure")
    pv.add_argument("--bucket", action="append", help="extra honeytoken bucket(s) to watch")
    pv.add_argument("--allow-empty", action="store_true",
                    help="allow provisioning with no bucket selector (NOT recommended)")
    pv.set_defaults(func=cmd_provision)

    pi = sub.add_parser("ingest", help="pull S3 access events from SQS into the store")
    pi.set_defaults(func=cmd_ingest)

    pb = sub.add_parser("probe", help="run outbound public-AI probe (confirmation-gated)")
    pb.add_argument("--confirm", action="store_true",
                    help="confirm you accept the ToS risk and run enabled tools")
    pb.set_defaults(func=cmd_probe)

    st = sub.add_parser("status", help="correlation dashboard / report")
    st.add_argument("canary_id", nargs="?", help="limit to one canary")
    st.add_argument("--json", action="store_true", help="emit JSON instead of text")
    st.set_defaults(func=cmd_status)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
