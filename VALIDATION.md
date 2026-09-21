# Verification record and candid outcome

Built and exercised on 2026-09-20; renamed to FraudGraph and verified again on 2026-09-21 at the user’s request. All local fixtures, UI-seeded payments, security tests and load-test transactions are **synthetic**. The separate IBM AMLSim benchmark is **external synthetic** banking data. No real UPI transaction data was obtained, simulated records are never described as observed UPI traffic, and no detection-accuracy claim is made for real users.

## What works and what is not established

The delivered single-node service runs, accepts a transaction stream, commits it durably, produces reproducible rule explanations, enforces role restrictions, and supports actual browser case review. Independent external detection validation **failed**. The system is therefore a functioning investigation implementation with explicitly limited detection coverage, not a validated production fraud service.

## Independent data result

The frozen `fanin-fanout-v1.0.0` rule was evaluated on every one of IBM AMLSim v2.1 `bank_mixed`'s **885,744 transactions** and **20,000 accounts**. Source timestamps and amounts were preserved; no labels enter detection, no dates were compressed, and no thresholds were changed after seeing results. See [DATASET.md](DATASET.md) for exact download links, hashes, schema and reproduction.

| Metric | Actual result | Computation |
| --- | ---: | --- |
| TP / FP / FN / TN, ever-alerted accounts vs SAR labels | 0 / 0 / 753 / 19,247 | Set intersection/difference of predicted and labelled accounts |
| Recall | 0% | 0 / (0 + 753) |
| Precision | Undefined | 0 / (0 + 0), stored as JSON null |
| Gather-scatter hubs detected | 0 / 50 | Label-derived hubs compared only after predictions frozen |
| Candidate window matches | 0 | All 1,675,092 account/timestamp evaluations |

The data has only daily timestamps, and its 50 gather-scatter patterns span 9–29 days. No strictly ordered events fit this detector's largest two-hour window. Only 31 of those hubs have four sources and four recipients even across the full labelled pattern. Generic SAR accounts also include non-hub participants. These facts explain the incompatibility; they do not turn the failure into a successful benchmark. Predicting everything negative yields a superficially attractive accuracy number; it is deliberately not a success metric here.

The complete acquisition/replay was repeated from a fresh download. [Primary results](evidence/public_evaluation.json) and [reproduction](evidence/public_reproduction.json) agree on data hashes, detector hash, metrics, and coverage. There is no real-world precision/recall estimate.

## Adversarial findings

The adversarial script runs chronological replay as well as final snapshots. Ground truth below is the fixture author's declared intent, not independently observed crime. Tests that assert a known evasion are expected to pass while the detector misses the attack.

| Constructed synthetic case | Observed behavior | Why |
| --- | --- | --- |
| Canonical six-source / six-recipient hub | Detected | Matches the frozen predicates |
| Motif across fixed five-minute bucket boundary | Detected | Windows slide with event time |
| Ordinary merchant, one supplier payout | No alert | Fewer than four recipients |
| Legitimate six-in / six-out aggregator | **False positive** | Payment shape is indistinguishable without business context |
| Fan-in followed by payouts more than two hours later | **Evades** | No complete configured window |
| Four coordinating hubs sharing recipients, three sources/recipients each | **Evades** | No group-level or two-hop rule |
| Recipients reused from source set | **Evades** | Fails fresh-recipient fraction |
| Each inflow immediately drained | **Evades** | Too few payouts after the fourth source establishes collection |
| Only 60% of collected value redistributed | **Evades** | Below 65% ratio predicate |
| Payouts before inflows | No alert | Correct temporal negative control |

Evidence is in [adversarial.json](evidence/adversarial.json); `scripts/run_adversarial.py` reproduces it. The scenarios probe predicates and do not constitute an unbiased population for accuracy calculations. No aggregate synthetic accuracy is reported.

## Measured near-real-time behavior

An isolated real Uvicorn process received **1,600 HTTP transaction requests**, one transaction per request: 100 independent 12-payment synthetic rings plus 400 independent benign transfers. It persisted **1,600 transactions and 100 cases**, verified again after server restart. These expected case counts test the chosen workload, not real-world accuracy.

The measured submission loop lasted **6.891530584 seconds**, giving **232.1690 transactions/second** (`1600 / elapsed_seconds`). Request round-trip nearest-rank p50/p95/p99 were **3.9468 / 6.6604 / 9.3120 ms**. The 100 requests that first completed a detectable pattern returned their first alert acknowledgments with p50/p95/p99 **4.1930 / 7.1092 / 8.6072 ms**. Durability is included in the acknowledgment.

The earlier pre-final run measured 249.3166 transactions/second and 5.2140 ms p95; it is retained in `evidence/http_benchmark_initial.json`. The final-build run above includes transactional session rechecks. Host load also varies, so the difference cannot be attributed solely to code changes.

Every request and first-alert timing sample, percentile formula, runtime version, hardware description, and validation assertion is saved in [http_benchmark.json](evidence/http_benchmark.json). The measurement used a single sequential client, one worker, SQLite, loopback HTTP on an Apple M1 with 8 GiB RAM, small independent hubs and a short run. It excludes production network/TLS latency, sustained traffic, many concurrent clients, hot accounts and large historical tables. It is not a safe capacity limit, throughput guarantee, national-scale benchmark, or end-to-end bank-feed latency. The dashboard polls at two-second intervals, adding up to approximately one polling interval under normal responsive conditions; no browser-latency distribution was measured.

## Functional and security verification

The final suite contains **78 passing tests plus 24 passing subtests**. The exact count/duration is in [tests.xml](evidence/tests.xml). It covers rule invariants, adversarial fixtures, HTTP application behavior, persistence, concurrency/idempotency, event-time replay, exact review snapshots, and an independent security suite. Two third-party deprecation warnings are preserved; they concern the installed test client and AnyIO alias, not failed assertions.

The separately booted real-server probe recorded **24 successful HTTP assertions**, including denied anonymous/role/origin/CSRF requests, malformed CSRF denial, ingestion, duplicate handling, case review, stale-version conflict, restart, deactivation and logout-token rejection. See [security_live.json](evidence/security_live.json) and [SECURITY.md](SECURITY.md). The server was actually started and contacted through sockets; these are not mocked endpoint results.

Browser verification used the actual application through the Codex in-app browser. It exercised login, case selection, evidence/graph display, persisted assessment, literal HTML-like input in a note, admin audit navigation, logout, a lower-role login, and a 390×844 responsive viewport. The stored `<img ...>` string remained text: zero image nodes were added to the review history. A viewer had no visible assessment or user-management control. On logout, inspected case text, review history, audit rows and user list were empty; password fields were blank. The mobile document width was 390 px at a 390 px viewport, and sign-out remained available. [browser_checks.json](evidence/browser_checks.json) records these observations. Browser tests were interactive tool-driven verification, not a packaged headless cross-browser suite. No screen-reader audit or full WCAG conformance test was performed.

The initial dependency audit found ten advisory records (including duplicate GHSA/PYSEC aliases) for the venv's pip 25.3 installer. The isolated installer was updated to 26.2.1 and the pinned environment was checked again. Original and final feed results are retained as [before](evidence/dependency_audit_before.json) and [after](evidence/dependency_audit.json). This is a query of the official PyPI release advisory feed, not proof against unknown vulnerabilities or malicious packages.

## Mistakes and corrections retained in the record

1. Initially selected a website-hosting workflow, then corrected the choice to a standalone persistent service before initializing or deploying a Site.
2. Initially secured only the main SQLite file after WAL creation; the reviewer reproduced broadly readable sidecars. Owner-only precreation fixed it, and a regression checks all files.
3. The initial SQL INSERT had one extra placeholder. It was fixed and successful ingestion tested. An early replay range also omitted newer events in mixed-time batches; earliest/latest bounds and a regression fixed that omission.
4. Non-ASCII CSRF input originally produced HTTP 500. TestClient and real HTTP reproduced it; explicit ASCII validation now returns 403.
5. Logout originally hid rather than cleared the prior workspace. Sensitive state/DOM clearing and an authentication-generation guard were added, then browser-verified.
6. A cookie assertion incorrectly expected a trailing semicolon after `Secure`, producing a false test failure. It was replaced with parsing via `SimpleCookie`; the actual cookie was already secure.
7. The first downloader transport failed host TLS-chain validation. Certificate-verifying system curl succeeded, and fresh download/replay reproduced the results. TLS verification was not disabled.
8. The first `pip-audit` command used an incompatible flag; the corrected invocation timed out in its Python HTTPS client. A reproducible certificate-verifying curl client queried the official PyPI feed, found the installer advisories, and drove the upgrade.
9. A final reviewer reproduced two administrators concurrently disabling one another and leaving zero active admins. Authorization is now rechecked inside the write transaction, and the last active administrator is protected. New regressions also cover ingestion revoked before commit and an old-password login racing a password change.
10. Mobile styling initially hid sign-out. It was corrected and verified at 390 px. Graph labels were also shortened to preserve distinct suffixes instead of showing indistinguishable prefixes.

## Remaining uncertainty

Known adversarial misses and false positives remain. No independent matched intraday UPI benchmark, real bank integration, institutional pilot, licensed real labels, high-degree sustained load, fault-injected disk/OS crash test, backup restoration drill, production TLS deployment, MFA/SSO integration, multi-tenant access control, independent penetration test or compliance assessment has been completed. The source includes implementation, tests and reproducible evidence; it does not justify deploying unsupervised against real customer accounts.
