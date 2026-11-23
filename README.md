# LLM SOC Log Triage (AI-02)

**A Claude-powered Tier-1 SOC assistant: it reads raw Suricata / Wazuh alerts and returns a structured triage decision as JSON.**

Diploma project AI-02, ACSP Cybersecurity track, UM6P (July 2026).
Author: **Brahim EL HANATI**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Anthropic](https://img.shields.io/badge/Anthropic%20API-Claude%20Opus-D97757)
![Structured output](https://img.shields.io/badge/output-JSON%20schema-2ea44f)

---

## The problem

IDS and SIEM sensors produce a constant stream of terse alerts full of signature IDs, ports and protocol jargon. For a junior analyst or a small team without a mature SOC, the hard part is usually not detection but **interpretation**: what does this alert mean, how urgent is it, and what should I do first?

AI-02 works as a **first-pass assistant**. For each log line it gives:

| Field | Content |
|---|---|
| `severity` | `critical` / `high` / `medium` / `low` / `info`. This is a closed enum, so it can be scored |
| `attack_type` | a short label, e.g. Brute Force, SQL Injection, Malware / C2, None / Benign |
| `summary` | one sentence explaining what the log shows |
| `recommended_action` | the concrete next step: block, isolate, escalate to Tier-2, close as benign |

The analyst confirms or overrides the result. The tool does not replace them.

## Results on the 10-log benchmark

The benchmark (`samples.txt`) mixes **5 realistic alerts** (L1–L5) and **5 deliberate edge cases** (L6–L10). The edge cases test the model with a privileged-account login, a single failed login, an alert with **no IP address**, an authorised internal scanner and a routine agent restart.

| Metric | Result |
|---|---|
| Severity accuracy (vs. hand-labelled ground truth) | **9 / 10** |
| Invented indicators (IPs, hosts, ports, users not in the log) | **0 / 10**, checked manually |
| Schema-valid JSON | **10 / 10** |
| Cost of the full run | ≈ **$0.07** |
| Latency | 2–5 s per log, with one 21.7 s outlier |

| # | Alert | Severity | Attack type |
|---|---|---|---|
| L1 | Nmap NSE user-agent against a web host | medium | Reconnaissance |
| L2 | 18 failed root SSH logins from an external IP | high | Brute Force |
| L3 | `UNION SELECT` against `products.php` | high | SQL Injection |
| L4 | Rootcheck: hidden file in `/dev` on db-srv-03 | critical | Malware / C2 |
| L5 | Cobalt Strike beacon from an internal host | critical | Malware / C2 |
| L6 | SSH success for `badmin` from an internal IP | info | None / Benign |
| L7 | One failed SSH login for `jdupont` | low | Suspicious Login |
| **L8** | Spamhaus DROP match, **no IP in the log** | **medium** ✗ (expected low/info) | Malware / C2 |
| L9 | Nessus scan from the authorised internal scanner | info | Reconnaissance |
| L10 | Wazuh agent started | info | None / Benign |

Full model output for every log: [`results.csv`](results.csv).

**Notable cases**

- **L8, the only miss, errs on the safe side.** The model rated it medium instead of low/info, so it raised attention rather than suppressing it. It was also built as a hallucination trap: the log names a malicious netblock but gives no address. The summary refers only to "a known malicious or hijacked netblock" and **does not invent an IP**.
- **L9, the authorised scanner.** By signature it looks like hostile scanning, but the model read the context and closed it as benign after confirmation. That kind of judgement is what reduces false-positive fatigue.
- **L4 / L5.** Both got critical severity with an *isolate the host and escalate to IR* action.

## How it works

```
log line ─► system prompt (from categories.json) + log ─► Claude (streamed) ─► JSON-schema-constrained reply ─► 4-field record ─► stdout / CSV
```

- **Model:** `claude-opus-4-8` through the official `anthropic` SDK. It is a hosted model, so there is no GPU, no training data and no fine-tuning, and behaviour is steered by the prompt.
- **Structured output:** the request includes a JSON schema with `severity` restricted to the enum in `categories.json` and `additionalProperties: false`. Every reply can therefore be parsed and scored.
- **Prompt:** the model acts as a SOC Tier-1 analyst, judges severity from the log alone, and labels benign activity `None / Benign` with severity `info` or `low`.
- **Streaming:** tokens are printed to **stderr** as they arrive. Clean JSON records go to **stdout**, so `> out.jsonl` stays clean.
- **Debugging:** `--debug` prints the full request payload and the raw response, including token usage.
- **Mock mode:** `--mock` runs a keyword heuristic instead of the API, to test the pipeline without a key.
- **Configurable:** you can change the analyst framing, the severity levels and the attack-type hints in `categories.json` without touching any code.

## Quick start

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # then put your own key in .env
```

```bash
# one alert, live streamed
python classifier.py "ET SCAN Nmap Scripting Engine User-Agent Detected"

# whole benchmark, with full JSON debugging and CSV export
python classifier.py --file samples.txt --debug --csv results.csv

# offline pipeline check, no API key needed
python classifier.py --mock --file samples.txt
```

## Security notes

- The API key is read from the environment or a local `.env` file, which is git-ignored. It is never hard-coded.
- **Logs are untrusted input.** An attacker who controls log contents could try to steer the model with prompt injection. The JSON schema limits what comes back, but it does not make the content trustworthy.
- Logs can contain internal IPs, hostnames and usernames. Sending them to an external API has confidentiality implications that a real deployment must check against policy.

## Limitations

- Ten logs show the approach but are far too few for statistical claims. 9/10 and 0/10 are indicative only.
- I wrote both the benchmark and the labels myself, which can introduce bias.
- Each log was classified once. LLM outputs are not deterministic, so repeated runs would measure stability.
- The tool sees one alert at a time and cannot correlate a multi-stage attack the way a SIEM can.
- It depends on an external provider for availability, latency and cost.

## Roadmap

- A larger, independently labelled benchmark with repeated runs
- An explicit grounding rule in the system prompt ("never invent an IP, host, port, user or CVE not present in the log")
- A comparison across model tiers on cost and accuracy
- Batch / SIEM integration (e.g. reading from a Wazuh alerts file)

## License

MIT

## Contact

Brahim EL HANATI · [LinkedIn](https://www.linkedin.com/in/brahim-el-hanati) · See also: [ML-based IDS on UNSW-NB15](https://github.com/brael-hach/ml-ids-network-security)
