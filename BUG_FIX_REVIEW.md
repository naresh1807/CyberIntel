# Repository bug review — 5 October 2026

Reviewed desktop orchestration, storage/audit operations, collectors, configuration,
tabular/capture analysis, scanning, credentials, exports, and existing tests.

## Fixed defects

- Preserve provider Retry-After cooldowns on the final HTTP attempt, including
  the single-attempt certificate lookup. Handle overflowing Retry-After dates.
- Refresh cache entries whose collection timestamp is in the future.
- Accept internationalized top-level domains and return a validation error for
  invalid IDNA labels. Reject malformed URL ports and embedded whitespace.
- Parse HTTP content types without depending on letter case.
- Reject certificate rows without name data, invalid HIBP breach dates, and OTX
  responses without association counts rather than presenting empty successes.
- Turn malformed provider types and DNS network failures into unavailable results.
- Query absolute DNS names without resolver search-suffix expansion.
- Preserve synthetic GPS rows when the import is classified as inferred.
- Reject empty CSV/XLSX column headers before pandas invents names.
- Refuse malformed TShark rows and invalid packet lengths/timestamps instead of
  silently skipping packets or returning misleading statistics.
- Report TShark launch failures with an actionable application error.
- Check the analysis hash and evidence hash again before saving results, refusing
  findings when evidence changes during processing.
- Serialize concurrent workspace-open audit writes to prevent chain forks.
- Validate acquisition timestamps and nonexistent watch cases explicitly.
- Reject invalid Nmap XML port numbers with an application validation error.
- Preserve discovered names and per-family results after DNS socket failures.
- Handle overflowing numeric configuration settings without an uncaught exception.

## Verification

- Before changes: **135 tests passed**.
- After changes: **167 tests passed**, including 32 new regression cases in
  `tests/test_review_regressions.py` and the real TShark synthetic-capture test.
- `pip check`: no broken requirements.
- `git diff --check`: passed.
- Installer and packaging shell scripts: `bash -n` passed.
- `scripts/verify_demo.py`: completed; three-page synthetic PDF and a valid audit
  chain. Generated screenshots, reports, and HTML are in ignored `artifacts/`.

Live external APIs, paid lookups, active target scans, installation, and packaged
bundles were not exercised. This review does not establish that every possible
defect has been eliminated.
