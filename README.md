# malware-packages

Processes [OSSF malicious-packages](https://github.com/ossf/malicious-packages) into lightweight JSONL files per ecosystem for fast consumption by OSSShield and similar tools.

## Output

One JSONL file per ecosystem in `malicious/`:

- `npm.jsonl`
- `pypi.jsonl`
- `go.jsonl`
- `maven.jsonl`
- `nuget.jsonl`
- `crates.io.jsonl`
- `rubygems.jsonl`

Each line: `{"name":"package-name","id":"MAL-2022-3"}` (id from OSV report; versions optional when available).

## Usage

```bash
npm install
npm run process        # Full processing (CI)
npm run process:test  # Local: limit 10 packages per ecosystem
npm run process -- --limit 20  # Custom limit
```

Uses `git clone` to fetch [OSSF malicious-packages](https://github.com/ossf/malicious-packages) (no API).

## Pipeline

A GitHub Action runs twice daily (00:00 and 12:00 UTC) to process and commit the output files. Push to `depgate/malware-packages` to publish.
