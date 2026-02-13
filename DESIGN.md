# Guardian SIEM - Architectural Decision Records

> This document captures the key engineering trade-offs made during Guardian SIEM's development.  
> Each record follows the [ADR format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) used in professional software teams.

---

## ADR-001: SQLite over Elasticsearch for Event Storage

**Date:** 2025-01-15  
**Status:** Accepted  
**Context:**  
Guardian SIEM needs persistent, queryable storage for security events. The industry default is Elasticsearch (used by Splunk, ELK stack, Wazuh, etc.) because it provides full-text indexing, sub-second search across billions of records, and native Kibana integration.

However, Elasticsearch requires:
- A JVM runtime consuming 4-8 GB RAM at idle
- A separate cluster management layer (indices, shards, replicas)
- Complex YAML tuning to avoid OOM kills on small machines
- External dependency management (Java, curl-based health checks)

**Decision:**  
Use Python's built-in `sqlite3` module with WAL (Write-Ahead Logging) mode for all event, cache, and user storage.

**Reasoning:**
1. **Zero-dependency deployment** — sqlite3 ships with Python's standard library. No JVM, no Docker sidecar, no heap tuning. A SOC analyst can `git clone` and `pip install -r requirements.txt` on any machine.
2. **Single-file portability** — The entire event history is one `.db` file that can be copied, backed up with `cp`, or emailed to a colleague for offline analysis.
3. **Write performance is sufficient** — SQLite in WAL mode handles ~50,000 inserts/second on modern SSDs. Guardian's event pipeline (network capture + log ingestion + syslog) produces, at most, a few thousand events/second in a lab environment.
4. **Query complexity is low** — Guardian's access patterns are simple: insert events, query by timestamp + severity + source, aggregate counts. These map cleanly to indexed SQL queries without needing inverted indices.

**Trade-offs accepted:**
- Full-text search is not supported. Events are searched via SQL `LIKE` and regex, not tokenized inverted indices. This becomes slow past ~500K rows.
- No native clustering. If Guardian were deployed as a distributed fleet, each node would have its own database.
- Concurrent write contention under heavy load. SQLite locks the entire database during writes, which could bottleneck a multi-threaded ingestor.

**Upgrade path:**  
The `EventBus.emit()` method is the single insertion point. Swapping SQLite for PostgreSQL or Elasticsearch requires changing only this class — all consumers use the same `query()` API. This was an intentional design choice to keep the storage layer pluggable.

---

## ADR-002: Event Bus Singleton Pattern for Module Decoupling

**Date:** 2025-01-15  
**Status:** Accepted  
**Context:**  
Guardian has multiple data producers (Passive IPS, Log Ingestor, Syslog Receiver) and multiple consumers (Rules Engine, SIGMA Engine, MITRE Tagger, Threat Intel, GeoIP, Alert Manager, Active Response, Dashboard WebSocket). Without a central broker, each producer would need direct references to every consumer — creating an O(N*M) coupling problem that makes adding new modules painful.

**Decision:**  
Implement a singleton `EventBus` class that all producers emit to and all consumers subscribe to. Events flow through a single pipeline: `emit() -> store in DB -> notify subscribers`.

**Reasoning:**
1. **Adding a new module requires zero changes to existing code.** When I built the Syslog Receiver (module #14), I added one line: `bus.emit(source, severity, message)`. No existing module was touched.
2. **Consistent enrichment pipeline.** Every event, regardless of source, passes through the same enrichment chain: Rules → SIGMA → MITRE → Threat Intel → GeoIP → Alert → Active Response. This guarantees uniform data quality.
3. **Testability.** Unit tests can instantiate `EventBus()` in isolation, emit synthetic events, and assert on query results without spinning up Flask, Scapy, or socket servers.

**Trade-offs accepted:**
- Single point of failure. If the EventBus thread deadlocks, the entire pipeline stalls. Mitigated by keeping the emit path simple (DB insert + iterate subscribers).
- No backpressure. If a subscriber (e.g., Threat Intel API call) blocks, it delays subsequent subscribers for that event. In production, subscribers should be non-blocking or use a queue.
- Singleton pattern limits to one bus per process. Acceptable for a single-host SIEM; would need refactoring for a distributed architecture.

**Alternatives considered:**
- **Redis Pub/Sub**: Better performance and built-in backpressure, but adds an external dependency and deployment complexity.
- **Python `asyncio` with `Queue`**: More Pythonic concurrency, but would require rewriting all modules to be async — a large refactor with marginal benefit at current scale.
- **ZeroMQ**: Excellent for distributed event pipelines, but overkill for a single-process prototype.

---

## ADR-003: Passive-Only Network Monitoring (No Inline Blocking)

**Date:** 2025-01-15  
**Status:** Accepted  
**Context:**  
Network IPS/IDS systems fall into two categories:
- **Inline (IPS):** Sits between network segments, can drop malicious packets in real time. Risk: misconfiguration blocks legitimate traffic, causing outages.
- **Passive (IDS/NSM):** Mirrors traffic via a span port or tap, analyzes copies. Cannot block, but cannot cause outages.

Guardian's `passive_ips.py` uses Scapy in `sniff()` mode — read-only packet capture.

**Decision:**  
Guardian operates as a passive Network Security Monitor (NSM). The `active_response.py` module operates at the host firewall level (Windows Firewall via `netsh`), not at the network packet level.

**Reasoning:**
1. **Safety guarantee.** A SIEM should never be the reason your network goes down. Passive mode means Guardian can be deployed on a production network with zero risk of disruption, even if a rule is misconfigured.
2. **No special hardware required.** Inline IPS needs two NICs and network reconfiguration (bridge mode). Passive sniffing works on any NIC in promiscuous mode.
3. **Defense in depth.** The active response module blocks at the host firewall layer, which is orthogonal to network monitoring. A bad block rule affects only the Guardian host, not the network path.

**Trade-offs accepted:**
- Cannot prevent attacks in real time at the network level. Guardian detects and alerts; a human or a separate IPS (Suricata, Snort) does the blocking.
- Active response is Windows-only (`netsh advfirewall`). Linux/macOS would need `iptables`/`pf` equivalents.

**Safety controls built in:**
- Active response is **disabled by default** (`enabled: false`)
- Even when enabled, **dry-run mode** is on by default (`dry_run: true`)
- Private IP ranges and loopback are **permanently whitelisted** (can never be blocked)
- Rate limiter caps at 20 blocks/hour to prevent runaway automation
- All actions logged to an immutable audit trail

---

## ADR-004: SIGMA + YAML Dual Rule Engine (Not Either/Or)

**Date:** 2025-02-01  
**Status:** Accepted  
**Context:**  
Guardian started with a custom YAML rules engine (`rules_engine.py`) that uses regex pattern matching with threshold/window counting. This works well for network-level detections (port scans, traffic anomalies) but is non-standard — rules can't be shared with other SIEMs.

SIGMA is the industry-standard detection rule format used by Splunk, Elastic SIEM, Microsoft Sentinel, and ~50 other platforms. The SIGMA rule repository on GitHub contains 3,000+ community-maintained rules.

**Decision:**  
Run both engines in parallel. Native YAML rules for Guardian-specific detections, SIGMA rules for industry-standard detections. Both fire in the same event pipeline.

**Reasoning:**
1. **Compatibility with the SIGMA ecosystem.** Analysts can download rules from [SigmaHQ](https://github.com/SigmaHQ/sigma) and drop `.yml` files into `config/sigma_rules/` — no conversion needed.
2. **Native rules are better for threshold-based detections.** SIGMA doesn't support sliding-window thresholds natively (it's a detection description, not a stateful engine). Guardian's YAML rules handle "5 failed logins in 60 seconds" more naturally.
3. **Gradual migration path.** Teams can start with Guardian's simpler YAML format and adopt SIGMA rules as their detection maturity grows.

**Trade-offs accepted:**
- Two rule formats means two code paths to maintain.
- SIGMA support is a practical subset, not 100% spec-complete. Missing: aggregation expressions (`count() > 5`), `near` temporal proximity, and full `|base64` modifier decode. These are rarely used in practice and can be added incrementally.

---

## ADR-005: bcrypt with SHA-256 Fallback for Authentication

**Date:** 2025-02-01  
**Status:** Accepted  
**Context:**  
The dashboard authentication module needs password hashing. Options considered:
- **bcrypt**: Industry standard, adaptive cost factor, resistant to GPU cracking. Requires the `bcrypt` C extension (wheel or compile).
- **argon2**: Winner of the 2015 Password Hashing Competition. Better than bcrypt theoretically, but the `argon2-cffi` package has complex native dependencies.
- **PBKDF2 (hashlib)**: Built into Python's standard library. Widely deployed but slower to hash and faster to crack than bcrypt at equivalent parameters.
- **SHA-256 (hashlib)**: Not a password hash — no salt, no cost factor. Trivially crackable with rainbow tables.

**Decision:**  
Use `bcrypt` as the primary password hasher. If `bcrypt` is not installed, fall back to salted SHA-256 with a logged warning.

**Reasoning:**
1. **bcrypt is the correct default.** It's battle-tested, supported everywhere, and the `bcrypt` Python package installs cleanly via pip on Windows/Linux/macOS.
2. **Graceful degradation** keeps Guardian functional even in constrained environments where native extensions can't be compiled (e.g., locked-down corporate laptops, air-gapped networks).
3. **The fallback warns loudly.** When SHA-256 is used, Guardian prints a startup warning and logs it — this is a conscious trade-off, not a silent downgrade.

**Trade-offs accepted:**
- SHA-256 fallback is cryptographically weak for password storage. It's salted (not rainbow-tableable) but has no work factor — a GPU can try billions of hashes/second.
- No support for argon2, which would be ideal. Added as a future enhancement.

---

## ADR-006: Report Generation with PDF Primary, HTML Fallback

**Date:** 2025-02-01  
**Status:** Accepted  
**Context:**  
Security teams need exportable reports for management, compliance, and incident documentation. The two common formats are:
- **PDF**: Professional, printable, universally readable. Requires `reportlab` (40MB dependency with C extensions).
- **HTML**: Lightweight, no dependencies, viewable in any browser. But looks "unprofessional" when emailed to executives.

**Decision:**  
Generate PDF reports using `reportlab` when available. Fall back to self-contained HTML reports (inline CSS, no external assets) when `reportlab` is not installed.

**Reasoning:**
1. **PDF is the expected deliverable** in corporate security. SOC teams share PDFs with CISOs, auditors, and legal. An HTML file attachment raises eyebrows.
2. **HTML fallback ensures the feature always works.** `reportlab` is a large optional dependency with C extensions. In environments where it can't be installed, the HTML output is still professionally formatted and functional.
3. **Both formats use the same data-gathering pipeline** (`_gather_data()`), so there's no logic duplication — only rendering differs.

**Trade-offs accepted:**
- `reportlab` is not installed by default (commented in requirements.txt). Users must opt in.
- HTML reports lack the polished layout of PDF (no page breaks, no vector charts). Good enough for quick sharing, not for board presentations.

---

## ADR-007: Syslog on Port 1514 (Not 514)

**Date:** 2025-02-01  
**Status:** Accepted  
**Context:**  
The standard syslog port is UDP/TCP 514. On Linux, binding to ports below 1024 requires root privileges. On Windows, port 514 may conflict with existing syslog daemons or corporate agents.

**Decision:**  
Default syslog listeners to port 1514 (both UDP and TCP).

**Reasoning:**
1. **No admin/root required.** Guardian can run as a normal user, which is safer and simpler for lab environments.
2. **No conflicts with existing infrastructure.** Corporate syslog collectors (rsyslog, syslog-ng, Splunk forwarder) often already occupy port 514.
3. **Industry precedent.** OSSEC/Wazuh uses port 1514 for its agent communication. Security practitioners are familiar with high-numbered ports for SIEM agents.

**Trade-offs accepted:**
- Network devices with hardcoded syslog destination port 514 will need reconfiguration or a port-forwarding rule.
- Configurable via `config.yaml` — users who need port 514 can change it and run with elevated privileges.
