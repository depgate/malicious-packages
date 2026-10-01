# malicious-packages

Processes [OSSF malicious-packages](https://github.com/ossf/malicious-packages) into lightweight,
incrementally consumable JSONL files per ecosystem for fast consumption by DepGate/OSSShield and similar tools.

## Output

Everything lives in `malicious/` and is committed to this repository, so it can be fetched with
`git clone --depth 1` or over raw GitHub HTTP
(`https://github.com/depgate/malicious-packages/raw/refs/heads/main/malicious/<file>`).

| File | Purpose |
|------|---------|
| `manifest.json` | Feed metadata: schema version, run timestamp, upstream commit, per-file hashes and counts |
| `<ecosystem>.jsonl` | Full snapshot: one record per malicious package, sorted by `name` |
| `<ecosystem>.changes.jsonl` | Rolling window (default 180 days) of upsert/delete operations, newest first |

Ecosystems: `npm`, `pypi`, `go`, `maven`, `nuget`, `crates.io`, `rubygems`, `vscode`,
`vscode-open-vsx.org` (the upstream ecosystem `vscode:open-vsx.org`; `:` is replaced by `-` in file names).

### Snapshot record (`<ecosystem>.jsonl`)

```json
{"name":"embiggen","id":"MAL-2026-5314","aliases":["GHSA-xxxx-xxxx-xxxx"],"versions":["0.11.97"],"published":"2026-06-06T06:13:57Z","modified":"2026-09-27T03:23:00Z"}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `name` | yes | Package name as published in the registry. Unique within a file. |
| `id` | usually | Primary OSV identifier (`MAL-YYYY-N`). When several upstream reports cover the same package, the lowest id is primary and the others are listed in `aliases`. |
| `aliases` | no | Other identifiers for the same finding (`GHSA-*`, `SNYK-*`, additional `MAL-*`). Sorted. |
| `versions` | no | Malicious versions. **Omitted means every version of the package is malicious** (OSV range `introduced: "0"`). Sorted. |
| `published` | no | Earliest upstream `published` timestamp across merged reports. |
| `modified` | yes | Feed-level timestamp of the run in which this record was added or last changed. Use it as the sync watermark. |

All reports for a package are merged into one record. Withdrawn upstream reports are excluded;
a package whose reports are all withdrawn disappears from the snapshot and produces a `delete` op.

### Change operation (`<ecosystem>.changes.jsonl`)

```json
{"op":"upsert","modified":"2026-09-27T03:23:00Z","name":"embiggen","id":"MAL-2026-5314","versions":["0.11.97"],"published":"2026-06-06T06:13:57Z"}
{"op":"delete","modified":"2026-09-20T03:07:00Z","name":"some-false-positive"}
```

- `upsert` carries the full current record (same fields as the snapshot). Replace the stored row entirely.
- `delete` carries only `name`. Remove the row.
- The file contains at most one op per `name` (the newest), sorted by `modified` descending, then `name`.
- Ops older than `changes_window_days` (see manifest) are pruned.

### Manifest (`manifest.json`)

```json
{
  "schema_version": "2.0.0",
  "generated_at": "2026-09-27T03:23:00Z",
  "upstream_repo": "https://github.com/ossf/malicious-packages.git",
  "upstream_commit": "af3e7b18d0e04aedeb9009af50f18a618b3da2d3",
  "changes_window_days": 180,
  "total_records": 238675,
  "ecosystems": {
    "npm": {
      "file": "npm.jsonl",
      "sha256": "...",
      "bytes": 29021645,
      "records": 221826,
      "changes_file": "npm.changes.jsonl",
      "changes_sha256": "...",
      "changes_records": 211,
      "max_modified": "2026-09-27T03:23:00Z"
    }
  }
}
```

`schema_version` follows semver: additive fields bump the minor version, breaking changes bump the major.
Consumers should reject a major version they do not understand.

## Consuming the feed

Store two things: the `generated_at` you last applied (the watermark) and, optionally, the per-file
`sha256` values. No release or version numbers need to be tracked; missed runs are harmless because
every snapshot is complete and the changes file is cumulative within its window.

1. Fetch `manifest.json`. If `generated_at` equals your watermark, stop.
2. For each ecosystem, skip it if the stored `sha256` matches.
3. If your watermark is within `changes_window_days` of `generated_at`, stream
   `<ecosystem>.changes.jsonl` and stop at the first line whose `modified <= watermark`.
   Apply in batches: `INSERT ... ON CONFLICT (name, ecosystem) DO UPDATE` for `upsert`,
   `DELETE ... WHERE name IN (...)` for `delete`.
4. Otherwise (first load, or offline longer than the window), bulk load `<ecosystem>.jsonl` into a
   staging table, upsert from it, and delete rows that are not present in the staging table.
5. Save `watermark = manifest.generated_at` and the new hashes.

A typical weekly sync is one small `manifest.json` request plus a few hundred rows.

### Which file to download

The client never needs both data files in the same sync. `manifest.json` is fetched every time;
then, per ecosystem, exactly one of the following applies (first matching row wins):

| # | Condition | Download | Apply | Mode |
|---|-----------|----------|-------|------|
| 1 | No stored watermark (first install) | `<eco>.jsonl` | bulk load all rows | `full` |
| 2 | `manifest.generated_at == watermark` | nothing | nothing; feed has not run since | `none` |
| 3 | stored `sha256[eco] == manifest.ecosystems[eco].sha256` | nothing | nothing; this ecosystem did not change | `skip` |
| 4 | `generated_at - watermark > changes_window_days` | `<eco>.jsonl` | stage, upsert, delete rows not in staging | `full` |
| 5 | otherwise | `<eco>.changes.jsonl` | read top-down, stop at first `modified <= watermark`; upsert / delete | `changes` |

After all ecosystems succeed: `watermark = manifest.generated_at`, `sha256[eco] = manifest.ecosystems[eco].sha256`.
If any ecosystem fails, do not advance the watermark; the next run repeats the (idempotent) work.

Typical lifetime of one client:

```
install    -> manifest + npm.jsonl          (row 1, full)       ~28 MB
week 1     -> manifest + npm.changes.jsonl  (row 5, changes)    ~30 KB
week 2     -> manifest only                 (row 2, none)       ~4 KB
week 3     -> manifest + npm.changes.jsonl  (row 5, covers weeks 2-3)
9 months   -> manifest + npm.jsonl          (row 4, full again)
```

### Reference client

`client/index.ts` implements the table above against a local `malicious/` folder. It has no
database; it keeps a small state file (`.client-state.json`: watermark + per-file hashes) and
reports, per ecosystem, which file it would download and how many rows it would upsert/delete.

```bash
npm run client                                   # inspect: full records and change ops per ecosystem
npm run client -- --first                        # first-time load (row 1), saves state
npm run client -- --next                         # subsequent sync using saved state (rows 2-5), saves state
npm run client -- --next --since 2026-09-27T03:23:00Z   # simulate a client with that watermark
npm run client -- --next --dry-run               # decide and report without saving state
npm run client -- --dir /path/to/malicious --state /tmp/state.json --json
```

## Usage

```bash
npm install
npm run process                     # full run, writes to malicious/ (CI)
npm run process:test                # smoke test: 10 packages per ecosystem -> .tmp-malicious-output/
npm run process -- --limit 20       # custom limit (also writes to .tmp-malicious-output/)
npm run validate                    # verify manifest hashes, counts, ordering
```

Flags: `--out <dir>` output directory, `--repo <dir>` reuse an existing upstream clone instead of
cloning (handy for local iteration), `--window-days <n>` changes window (default 180),
`--force` override the mass-delete guard.

The producer clones the upstream repo with `git clone --depth 1` (no API), merges all OSV reports
per package, and diffs the result against the previously committed snapshot. Records whose content
did not change keep their `modified` timestamp, so rewrites are deterministic and diffs stay small.

Safety guards: the run aborts without writing if the clone yields zero packages, or if any
ecosystem would delete more than 10% of its previous records (protects consumers from a bad
upstream fetch).

## Pipeline

A GitHub Action (`.github/workflows/process-daily.yml`) runs weekly (Sunday 00:00 UTC) and on
manual dispatch. It runs the producer, validates the output, and commits `malicious/` if anything
changed. Upstream OSSF data is updated daily, so the schedule can be tightened without code changes.
