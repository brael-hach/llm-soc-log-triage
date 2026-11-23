#!/usr/bin/env python3
"""AI-02 classifier — SOC Tier-1 triage of security logs using Claude.

Takes raw Suricata / Wazuh log lines and, acting as a SOC Tier-1 analyst, returns
for each line a JSON object with EXACTLY four keys:
  severity, attack_type, summary, recommended_action

Features:
  * Live API output — streams the model's JSON response token-by-token to stderr
    so you can watch each triage decision arrive in real time.
  * JSON debugging — `--debug` dumps the full request payload and the full raw
    response JSON, including token usage.
  * Structured output — the model is constrained to a JSON schema, so results are
    always machine-parseable.
  * CSV export — `--csv results.csv` writes one row per log line.

Usage:
  py classifier.py "ET SCAN Nmap Scripting Engine User-Agent Detected"
  py classifier.py --file samples.txt --debug --csv results.csv
  echo "<log line>" | py classifier.py --stdin
  py classifier.py --mock --file samples.txt        # offline pipeline check
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time

DEFAULT_MODEL = "claude-opus-4-8"
FIELDS = ["severity", "attack_type", "summary", "recommended_action"]


def log(msg: str = "") -> None:
    """Write a line to stderr so it doesn't pollute stdout (the parsed result)."""
    print(msg, file=sys.stderr, flush=True)


def load_dotenv() -> None:
    """If ANTHROPIC_API_KEY isn't in the environment, read it from a local .env file.

    Tolerant of a bare key line (just `sk-ant-...` with no `KEY=` prefix).
    Keeps the key out of the shell history and out of this repo (.env is gitignored).
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(os.getcwd(), ".env"), os.path.join(here, ".env")):
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
                elif line.startswith("sk-ant-"):
                    os.environ.setdefault("ANTHROPIC_API_KEY", line)
        break


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not data.get("severity_levels"):
        raise ValueError(f"{path}: no 'severity_levels' defined")
    return data


def build_request(text: str, cfg: dict, model: str) -> dict:
    """Build the kwargs passed to messages.create / messages.stream."""
    levels = cfg["severity_levels"]
    examples = ", ".join(cfg.get("attack_type_examples", [])) or "use your judgment"
    system = (
        f"{cfg.get('task', 'Triage the security log.')}\n\n"
        "Return ONLY a JSON object with EXACTLY these four keys:\n"
        f"  - severity: one of {levels} (how urgent/impactful this is).\n"
        "  - attack_type: a short label for the technique or activity "
        f"(examples: {examples}).\n"
        "  - summary: one concise sentence explaining what the log indicates.\n"
        "  - recommended_action: the concrete next step a Tier-1 analyst should take "
        "(e.g. escalate to Tier-2, block source IP, isolate host, close as benign).\n\n"
        "Judge severity from the log alone. If the activity is benign or purely "
        "informational, use attack_type 'None / Benign' and severity 'info' or 'low'. "
        "Do not output anything outside the JSON object."
    )
    schema = {
        "type": "object",
        "properties": {
            "severity": {"type": "string", "enum": levels},
            "attack_type": {"type": "string"},
            "summary": {"type": "string"},
            "recommended_action": {"type": "string"},
        },
        "required": FIELDS,
        "additionalProperties": False,
    }
    return {
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": text}],
        "output_config": {
            "format": {"type": "json_schema", "schema": schema},
            "effort": "low",
        },
    }


def mock_response(text: str, cfg: dict) -> dict:
    """Offline stand-in so the pipeline can be exercised without an API key."""
    lowered = text.lower()
    rules = [
        (("sql", "union select", "or 1=1"), "critical", "SQL Injection"),
        (("nmap", "port scan", "scan", "masscan"), "medium", "Port Scan"),
        (("brute", "failed password", "authentication failure", "multiple login"), "high", "Brute Force"),
        (("malware", "c2", "beacon", "trojan"), "critical", "Malware / C2"),
        (("xss", "<script", "onerror="), "high", "Cross-Site Scripting"),
        (("exfil", "data transfer", "large outbound"), "high", "Data Exfiltration"),
    ]
    severity, attack_type = "low", "None / Benign"
    for keys, sev, atype in rules:
        if any(k in lowered for k in keys):
            severity, attack_type = sev, atype
            break
    return {
        "severity": severity,
        "attack_type": attack_type,
        "summary": "mock heuristic triage (no API call)",
        "recommended_action": "Replace with a live run for a real assessment.",
    }


def classify_live(client, request: dict, debug: bool) -> tuple[dict, object]:
    """Stream the response, echoing JSON tokens live to stderr. Returns (parsed, message)."""
    log("--- streaming model output (live) ---")
    chunks: list[str] = []
    with client.messages.stream(**request) as stream:
        for text in stream.text_stream:
            chunks.append(text)
            sys.stderr.write(text)
            sys.stderr.flush()
        message = stream.get_final_message()
    log("\n--- stream complete ---")

    raw_text = "".join(chunks).strip()
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        log(f"[warn] could not parse streamed text as JSON: {exc}")
        joined = "".join(b.text for b in message.content if b.type == "text")
        parsed = json.loads(joined)
    return parsed, message


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-02 SOC Tier-1 security-log classifier (Claude-powered).")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("text", nargs="?", help="A single log line to triage.")
    src.add_argument("--file", help="Triage each non-empty line of this file.")
    src.add_argument("--stdin", action="store_true", help="Read one log line from stdin.")
    ap.add_argument("--config", default="categories.json", help="SOC config (task + severity_levels).")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"Model id (default {DEFAULT_MODEL}).")
    ap.add_argument("--csv", help="Write results to this CSV path.")
    ap.add_argument("--debug", action="store_true", help="Dump full request + response JSON.")
    ap.add_argument("--mock", action="store_true", help="Skip the API; use offline heuristic.")
    args = ap.parse_args()

    # Resolve the config path relative to this script if not found in cwd.
    cfg_path = args.config
    if not os.path.exists(cfg_path):
        alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), cfg_path)
        if os.path.exists(alt):
            cfg_path = alt
    cfg = load_config(cfg_path)

    # Gather inputs.
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            inputs = [ln.strip() for ln in fh if ln.strip()]
    elif args.stdin:
        inputs = [sys.stdin.read().strip()]
    elif args.text:
        inputs = [args.text]
    else:
        ap.error("provide a log line, --file, or --stdin")
        return 2

    client = None
    if not args.mock:
        load_dotenv()
        try:
            import anthropic
        except ImportError:
            log("[error] the 'anthropic' package is not installed. Run: py -m pip install -r requirements.txt")
            return 1
        if not os.environ.get("ANTHROPIC_API_KEY"):
            log("[error] ANTHROPIC_API_KEY is not set. Put it in .env, or use --mock for an offline run.")
            return 1
        client = anthropic.Anthropic()

    results = []
    for i, text in enumerate(inputs, 1):
        log(f"\n=== log {i}/{len(inputs)} ===")
        log(f"line: {text!r}")
        request = build_request(text, cfg, args.model)

        if args.debug:
            log("--- request payload ---")
            log(json.dumps(request, indent=2, ensure_ascii=False))

        t0 = time.time()
        if args.mock:
            parsed = mock_response(text, cfg)
            message = None
        else:
            try:
                parsed, message = classify_live(client, request, args.debug)
            except Exception as exc:  # surface API errors clearly, keep going
                log(f"[error] API call failed: {type(exc).__name__}: {exc}")
                continue
        elapsed = time.time() - t0

        if args.debug and message is not None:
            log("--- raw response JSON ---")
            log(message.to_json())
        if message is not None:
            u = message.usage
            log(
                f"usage: input={u.input_tokens} output={u.output_tokens} "
                f"stop={message.stop_reason} ({elapsed:.2f}s)"
            )

        # Keep only the four expected fields, in order, plus the original log line.
        record = {"log": text}
        for k in FIELDS:
            record[k] = parsed.get(k, "")
        results.append(record)
        print(json.dumps(record, ensure_ascii=False))  # clean parsed result -> stdout

    if args.csv and results:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["log"] + FIELDS)
            writer.writeheader()
            writer.writerows(results)
        log(f"wrote {len(results)} rows -> {args.csv}")

    log(f"\n=== done: {len(results)}/{len(inputs)} triaged ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
