# Independent public-data validation — negative result

The independent benchmark is **IBM AMLSim v2.1 `bank_mixed`**, published by IBM's AMLSim maintainers. It is **external synthetic US/USD banking data**, not observed bank records, not UPI, and not data produced by this project. We did not train or tune the detector on it.

The frozen production rule detected **0 of 50 labelled gather-scatter hubs**. Against all SAR-labelled accounts, the confusion matrix is **TP 0, FP 0, FN 753, TN 19,247**. Recall is **0%** and precision is **undefined** because there are no predicted positives. This does not establish useful external detection performance. Reporting 96.235% accuracy would merely reward predicting every account negative, so it is not used as the success metric.

## Provenance and integrity

- Primary publisher documentation: [IBM AMLSim Download Example Data Set](https://github.com/IBM/AMLSim/wiki/Download-Example-Data-Set), v2.1 section. The wiki says that the generated data do not reflect real data.
- [Official v2.1 download linked by IBM](https://www.dropbox.com/sh/l3grpumqfgbxqak/AAAj0fIjtJI6n9fdIBy2V7Lia/banks/v2.1?dl=0). At acquisition this URL returned a ZIP, despite the `dl=0` parameter.
- Acquired and evaluated on 2026-09-20. The initial ZIP SHA-256 was `e36015be8c728dc0acdc437aa7ab494fdc24d3289c0090673b07de31ac12a5fa`. ZIP metadata can change on re-download; the evaluator verifies each actual compressed CSV's pinned hash below.
- Repository license: [Apache-2.0](https://github.com/IBM/AMLSim/blob/7338a4bcb1af9bcfea2201ad7daccfe2a4d569ca/LICENSE). The separately hosted v2.1 archive contains no separate license file. Applicability of that repository license to the Dropbox archive has not been independently established. The deliverable contains the downloader, provenance and computed results, not a redistributed copy of the raw dataset.

| Source file in `data/bank_mixed/` | SHA-256 |
| --- | --- |
| `accounts.csv.gz` | `c07436098bc13d345d52b9c063dbe08e674adf71b955c95c8907a1e3e54a602f` |
| `transactions.csv.gz` | `d32cd92994941ae61128a29e1d59ca828ae389d9a90aef962f281d450e676d08` |
| `alert_accounts.csv.gz` | `a17be41c7db8cfe78a9a28a1d38a48bfa91058bd4a7af72ee0661d473b16cbbb` |
| `alert_transactions.csv.gz` | `d32d38c93ec32c2fa38f3d55fbb4e8907811e61e3a1a8a438540fd37ef964336` |

Raw acquired files are excluded from this repository. A fresh verified download can be placed in the ignored `data/public-reproduction/` directory or any chosen directory separate from the application database. Original labels and publisher-derived graph features are never ingested into the detector.

## Actual contents and schema

Computed from the downloaded files, rather than assumed from publisher descriptions:

- **885,744 transactions**, **20,000 accounts**, all accounts observed in the stream.
- **807 SAR-labelled transactions**, **753 SAR-labelled accounts**; the account labels agree between the account table and alert membership table.
- **100 labelled patterns:** 50 gather-scatter, 30 scatter-gather, 20 cycles.
- **720 distinct daily timestamp groups**, from 2017-01-01 to 2018-12-21. Every timestamp is exactly midnight UTC. There are no intraday ordering observations.
- No duplicate transaction IDs, nonpositive amounts, or self-transfers were observed in the acquisition profile. The evaluator independently rejects duplicate IDs, unknown accounts, and invalid amounts.
- Amounts range from 45.00 to 2,996.94 in the source's **synthetic USD** units.

The transaction columns are `tran_id, orig_acct, bene_acct, tx_type, base_amt, tran_timestamp, is_sar, alert_id`. Detection receives only a namespaced transaction ID, source, destination, original timestamp, exact integer minor-unit amount, and the explicit `external_synthetic` provenance label. `is_sar` and `alert_id` are used only for evaluation.

The account file's `prior_sar_count` field is defined as a Boolean SAR label by the publisher schema despite its count-like name. The relevant account columns are `acct_id, acct_rptng_crncy, prior_sar_count`; the other simulated profile fields are not used. Alert membership contains `alert_id, alert_type, acct_id, is_sar`; the alert transaction table joins pattern type to transaction endpoints and timestamps for post-prediction coverage analysis.

## Frozen protocol and result

The evaluator imports the same `fraudgraph.detector.detect_account` used by the application. The evidence records both its versioned configuration and SHA-256 source hash and aborts if the file changes during evaluation. Configuration is frozen: 5-minute, 30-minute and 2-hour trailing event-time windows; at least four sources and four recipients; 65–135% flow ratio; at least 80% of recipients absent from the source set. A payout must be **strictly later** than the fourth distinct source arrival. Equal timestamps do not establish causal ordering.

All source rows are replayed in verified chronological order. Events with the same exact source timestamp are grouped and the affected accounts are evaluated after that entire timestamp group is visible. This avoids inventing chronology from CSV row order. Every original timestamp is preserved. USD decimal amounts are mapped exactly to integer USD cents in the core detector's historically named `amount_paise` field; they are **not converted to INR**. This does not change the rule's ratios, which have no absolute amount cutoff. No thresholds, labels, event times or amounts are changed to improve the outcome.

The run performed **1,675,092 account/timestamp evaluations** and produced **zero candidate window matches**. `evidence/public_evaluation.json` contains every count, formula, hash, interpretation, and the actual measured replay duration. Timing includes core rule execution and CSV parsing, excludes HTTP/auth/database work, and is not an API latency or production-throughput claim.

| Evaluation population | Positive truth | Detected positives | Recall |
| --- | ---: | ---: | ---: |
| All SAR accounts | 753 | 0 | 0% |
| Gather-scatter hubs, derived from labelled pattern edges | 50 | 0 | 0% |

The account-level confusion matrix treats an account as predicted positive if it is ever alerted during the whole replay. It is not a transaction-level classifier score. `precision = TP/(TP+FP)`, `recall = TP/(TP+FN)`, and `F1 = 2TP/(2TP+FP+FN)`. Precision is JSON `null` for a zero denominator.

## What failed and what the data can establish

All labelled gather-scatter patterns span **9–29 days**, and none fits inside the largest frozen 2-hour window. With no non-midnight timestamps, no strictly ordered pair of events can be observed inside any configured window. Only **31 of the 50 gather-scatter hubs** even have four sources and four recipients across their full labelled pattern. Also, generic SAR account labels include source/destination and cycle participants, while this rule is designed to flag consolidation/dispersal hubs.

These are meaningful limits of this fixed detector's operating definition and of cross-domain validation. The benchmark establishes reproducibility and a concrete external failure. It does **not** validate discrimination among real UPI money mules and legitimate businesses. No independent public dataset with labelled intraday UPI mule rings was acquired. Real deployment still needs appropriately permissioned UPI or closely matched intraday data, reviewed case outcomes, prospective replay and analyst validation, and separate threshold calibration with an untouched evaluation holdout.

We deliberately did not compress days into minutes or widen thresholds after seeing the result. Such an experiment would answer a different question and cannot replace this reported failure.

## Reproduce

Python 3 and system `curl` are required for the public downloader; detection itself has no dataset-specific dependencies. From the delivered project directory:

```sh
python3 scripts/evaluate_public.py --download --data-dir data/public-reproduction
```

This downloads the publisher ZIP over HTTPS with certificate verification, extracts only four fixed names, checks pinned SHA-256s, replays the source and writes `evidence/public_evaluation.json`. If the data are already downloaded:

```sh
python3 scripts/evaluate_public.py --data-dir data/public-reproduction
```

A changed source hash stops evaluation rather than silently substituting a new dataset. Source download availability remains controlled by the publisher.

## Acquisition and build corrections

Before evaluating the detector, we first acquired IBM's repository sample `20K_fanin200cycle200.tgz` at commit `7338a4bcb1af9bcfea2201ad7daccfe2a4d569ca`. That sample contains fan-in and cycle patterns but no declared gather-scatter patterns, so we selected the more directly relevant v2.1 public dataset **before any detector scoring**. The unused sample's metadata says 1,803 fraud nodes, while counting its `isFraud` field produces 1,804; we did not silently reconcile that discrepancy or mix those labels into the selected benchmark.

The first implementation of the reproducible downloader used Python `urllib`. Its real end-to-end test failed this host's TLS certificate-chain validation. We changed transport to system `curl` with HTTPS-only redirects and normal certificate checks, without an insecure-TLS workaround. The corrected downloader was then exercised against the actual source and the full detector replay repeated. This transport correction does not change the dataset or detection results.
