# Security review and deployment boundaries

This review began during the from-scratch build on 2026-09-20 and was repeated after the FraudGraph rename on 2026-09-21 by a separate implementation reviewer. It combines source inspection, negative API tests, and an isolated real-HTTP probe. All security-test payment records are **synthetic**. These checks do not establish fraud-detection accuracy on real UPI data or certify production security.

## Threat model

This is a **single-institution** system. Authorized admin, analyst and viewer users share the institution's alert data. The provenance selector separates real/supplied, locally synthetic, and externally synthetic transaction graphs; it is not a tenant authorization boundary. There is no per-team, per-region, or per-institution row-level isolation inside one installation.

The browser, request headers, transaction payloads, account identifiers, usernames and analyst notes are untrusted. The application process, host administrator, database directory and configured upstream ingestion operator are trusted. An attacker holding a valid ingestion credential can submit fabricated events: the application cannot independently establish that a bank transfer occurred. A stolen administrator session grants administrator actions until expiry/revocation.

Protected assets include transaction integrity, alert evidence, case decisions, account relationships, password hashes, bearer sessions, role assignments, audit records and availability. The application never blocks or freezes a real payment or account; escalation records an analyst decision.

## Authorization contract

| Action | Admin | Analyst | Viewer | Ingestor |
|---|---:|---:|---:|---:|
| Read metrics, detection configuration, alerts and evidence | Yes | Yes | Yes | No |
| Review, dismiss or escalate an alert | Yes | Yes | No | No |
| Submit transaction batches | Yes | No | No | Yes |
| List/provision/disable users and view audit | Yes | No | No | No |
| Run synthetic replay in development | Yes | No | No | No |
| Change own password and log out | Yes | Yes | Yes | Yes |

Unauthenticated data and mutation requests receive 401. Authenticated users outside the permitted role receive 403. UI controls do not establish authorization; server dependencies enforce it.

## Implemented controls inspected

- Argon2id password hashing using the configured Argon2 library; minimum password length enforced on provisioning and password change. There are no built-in default user accounts.
- Cryptographically random opaque sessions. The database stores a SHA-256 digest of the bearer token. Session cookies are HttpOnly and SameSite=Strict, and Secure in production. Tokens are not persisted to browser localStorage.
- Eight-hour absolute session lifetime. Logout, password changes and administrative account deactivation invalidate stored sessions. Current user activation and role are looked up on each authenticated request and rechecked with session expiry/revocation inside authenticated write transactions. Login issuance rechecks that the verified password hash has not changed before creating a session.
- Exact configured Origin matching for login and authenticated mutations, plus a random session-bound CSRF token for authenticated mutations. SameSite cookies supplement the explicit checks.
- Persistent username and peer-address login counters; generic invalid-credential responses; bounded password/input lengths.
- Parameterized SQL for user-controlled values. Strict transaction schemas, integer paise, a 100-transaction batch limit, a 128 KiB request-body limit and explicit detector work limits.
- Atomic ingestion: transaction writes, detector updates and audit entries commit or roll back together. Exact transaction retries are idempotent; conflicting reuse of an ID rejects the batch.
- Optimistic case-version checks prevent silent loss of a concurrent analyst decision. Prior analyst reviews remain stored.
- SQLite main database and new WAL/SHM files are owner-only. Audit update/delete triggers block modification through normal database operations. Security headers include a restrictive CSP, no-store, anti-framing, nosniff and HSTS in production.

The database owner can bypass audit triggers or read every stored record. These triggers are an application-integrity control, not tamper evidence against a host administrator.

## Findings discovered during the build

| ID | Original finding and evidence | Disposition |
|---|---|---|
| S1 | A fresh DB was chmodded to 0600 only after WAL initialization. Under the observed umask, `-wal` and `-shm` remained 0644 even after a committed user write, exposing database pages to other local OS users. Reproduced with isolated synthetic data and filesystem `stat`. | Fixed by precreating the main file with owner-only permissions before SQLite initialization and closing initialization connections. Independent WAL/main-file permission regression passed. |
| S2 | The first transaction INSERT used nine placeholders for an eight-column row. Direct normal and mixed-time `ingest()` calls both raised `OperationalError: table transactions has 8 columns but 9 values were supplied`. | Fixed to eight placeholders. Successful ingestion and full-batch rollback tests subsequently passed. This was an implementation error, not an accuracy result. |
| S3 | Source inspection found that a mixed-time batch tracked only its earliest affected timestamp and queried through earliest + two hours, potentially excluding a fresh complete motif when an older hub event shared the batch. Runtime reproduction of the original code was blocked by S2. | Fixed to retain earliest and latest affected timestamps. An independent regression submits one old hub event plus a complete fresh motif more than two hours later and verifies an alert. This is a verified regression pass, not a claim that the original faulty version was separately exercised. |
| S4 | A valid session with a non-ASCII CSRF header caused `secrets.compare_digest(str, str)` to throw, returning HTTP 500 instead of 403. Reproduced in TestClient and against a booted Uvicorn HTTP server using raw header byte `0xff`. | Fixed by rejecting non-ASCII/invalid-length CSRF values before comparison. The independent regression and real HTTP probe both returned 403 after the fix. |
| S5 | Frontend source inspection found logout/session-expiry hid the workspace without removing prior case details, notes, user list, audit rows or cached detail state. A later lower-privilege user in the same browser could inspect retained DOM content. This was a source finding; the reviewer did not claim an original-version browser exploit. | Source corrected: logout/session expiry clears sensitive DOM, input/textarea values and cached detail state; an authentication epoch rejects old in-flight responses. The reviewer inspected the correction. Browser behavior is verified separately by the implementation owner; this document does not count source inspection as a browser test. |
| S6 | The follow-up review reproduced a concurrent account-lifecycle bug: two administrators could deactivate each other, yielding two HTTP 200 responses and zero active administrators. Test requests were synchronized immediately before write-transaction acquisition to reproduce the timing; application source was unchanged. | Fixed by revalidating the caller/session inside write transactions and checking the active-administrator count under the same lock. Deterministic concurrent route requests now permit one deactivation, reject the other, and retain one active administrator. Additional passing race regressions verify ingestion cannot commit after session revocation and a login verified against an old password cannot issue a session after password rotation; only the mutual-deactivation defect was exercised before its fix. |

## Executed evidence

Executed independent tests: **41 passed**, with two nonfatal third-party deprecation warnings, in **9.90 seconds** after the FraudGraph rename and concurrency fixes. The JUnit results are saved at [`evidence/security_tests.xml`](evidence/security_tests.xml). The saved real-HTTP report at [`evidence/security_live.json`](evidence/security_live.json) records **24 passed checks**. These counts are observed command results, not estimates. The reproducible commands are:

```sh
python -m pytest tests/test_security_review.py -q --junitxml=evidence/security_tests.xml
python scripts/security_probe.py --output evidence/security_live.json
```

The independent suite covers strict monetary and timestamp types, self-transfers, malformed IDs and unknown fields, batch size, local file permissions, mixed-time detection, anonymous denial, the role matrix, cross-session CSRF, origin confusion, generic login failures, brute-force throttling, successful-login budget handling, spoofed forwarding headers in the application client, hashed bearer storage, logout, expired/tampered sessions, disabled users, password-change revocation, duplicate/conflicting retries, injected audit failure with full rollback, future timestamp poisoning, body/query limits, static traversal, SQL metacharacters, production cookies/headers/demo denial, provenance separation, stale analyst reviews, concurrent administrator deactivation, revoked authentication between request handling and commit, and concurrent password rotation during login.

The first complete 37-case regression run had **36 passes and one failure** for S4 before the fix; the fix was also validated through real HTTP. An additional regression then verified twelve successful logins do not exhaust the peer failure budget.

Frontend source inspection found account labels, analyst notes, usernames, audit details and SVG labels rendered with `textContent`/DOM node creation. No `innerHTML`, `eval`, or browser token-storage sink was found in `app.js`. This is source review; browser execution results are separate.

The real-HTTP probe starts a separate Uvicorn process on a random loopback port using an isolated temporary database and random credentials. It exercises actual socket requests, logs in multiple roles, ingests a synthetic motif, verifies review authorization and conflict handling, restarts the server to check persistent sessions/case state, disables a user, and checks logout-token reuse. It shuts down its server and removes its temporary database. Its report contains statuses and assertions, never passwords or bearer tokens.

## Residual risks and work before a real deployment

1. **Deployment identity and transport:** production TLS termination, certificate renewal, reverse-proxy configuration, OIDC/SAML, MFA, service-account credentials and secret rotation are not implemented or verified here. Uvicorn must run with `--no-proxy-headers` unless a trusted proxy configuration is deliberately supplied; reading `request.client` cannot undo Uvicorn's own proxy-header rewriting. Development HTTP is for loopback use only.
2. **Rate limiting and availability:** the implemented login counter is tied to username and peer address, with ten attempts per fifteen minutes; successful attempts are removed from the peer failure budget while existing failures remain. Failed attempts from shared NAT/proxy clients can therefore deny one another login, and distributed attackers are not bounded by a global account-independent abuse service. Authenticated query/ingestion traffic does not have a distributed rate limiter. No sustained hostile-network, slowloris, multi-host or institution-scale capacity test was performed.
3. **Recovery and storage:** SQLite provides durable local commits but not high availability or a distributed ingestion queue. Disk encryption, encrypted backups, key management, backup restoration, migration rollback, point-in-time recovery, data retention and secure deletion require operational design and rehearsal. File permissions do not encrypt records.
4. **Audit and privileged abuse:** audit is local and mutable by the database/host owner. Forward it to an independently controlled append-only store for stronger evidence. Not every 401/403 or read is audited. A compromised analyst can submit misleading reviews; dual approval and institution workflow controls are absent.
5. **Session and account operations:** absolute expiry exists, but no idle timeout, device/session inventory, MFA, self-service recovery or identity-provider deprovisioning integration. Admins can provision and deactivate users; this UI/API does not expose role editing or password recovery. Administrators cannot deactivate themselves through this API; concurrent cross-deactivation is prevented from removing the last active administrator.
6. **Ingestion trust:** sessions and RBAC authenticate the submitting application user, not the financial truth or provenance of each payment. Production ingestion requires a bank-authorized authenticated feed, source reconciliation, deduplication conventions, dead-letter handling and monitoring of 409/422/429/503 responses. Events more than 24 hours behind a source watermark are explicitly rejected. Work-budget rejection can stop a high-volume account's processing until an operator chooses a suitable ingestion/evaluation path; no queued retry worker is provided.
7. **Privacy and isolation:** this is one institution's installation. Do not host independent institutions or mutually restricted investigation teams in a shared database. Real account identifiers should be tokenized upstream where possible. No claims of regulatory compliance, legal sufficiency, or privacy review are made.
8. **Detection and software assurance:** documented adversarial evasions and false positives remain. A passing security suite is not a penetration-test certificate. Browser and dependency checks must be reviewed alongside their own saved reports, and dependencies need ongoing update management. Tests verify selected failures, not the absence of undiscovered vulnerabilities.

## References

Primary guidance consulted on 2026-09-20:

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

These references informed the checks; they are not certifications of this implementation.
