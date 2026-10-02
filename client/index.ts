#!/usr/bin/env node
/**
 * Reference client for the malicious-packages feed.
 *
 * The sync protocol needs one piece of client state, the watermark (the `generated_at` of the
 * last manifest applied), and makes one decision per sync:
 *
 *   no watermark, or watermark < manifest.changes_since   -> FULL     download every file in files[]
 *   watermark == manifest.generated_at                    -> NOTHING
 *   otherwise                                             -> CHANGES  download <eco>.changes.jsonl,
 *                                                                     apply ops until modified <= watermark
 *
 * Hashes in the manifest are used only to verify downloads, never to make decisions.
 *
 * Modes:
 *   (default)  inspect: per ecosystem, how many full records, shards and change ops exist, hash status
 *   --first    first-time load (no watermark): FULL for every ecosystem, then save the watermark
 *   --next     subsequent sync using the saved watermark, then save the watermark
 *
 * No database is involved; "apply" is simulated and reported as counts per ecosystem.
 *
 * Run: npm run client
 *      npm run client -- --first
 *      npm run client -- --next
 *      npm run client -- --next --since 2026-09-27T03:23:00Z   # simulate a client with that watermark
 * Flags: --dir <feed dir> --state <file> --dry-run (do not save state) --json
 */
import { createHash } from 'crypto';
import { readFile, writeFile } from 'fs/promises';
import { join, resolve } from 'path';

type ManifestFile = {
  file: string;
  sha256: string;
  bytes: number;
  records: number;
};

type ManifestEcosystem = {
  files: ManifestFile[];
  records: number;
  bytes: number;
  changes_file: string;
  changes_sha256: string;
  changes_bytes: number;
  changes_records: number;
  max_modified: string | null;
};

type Manifest = {
  schema_version: string;
  generated_at: string;
  upstream_commit: string | null;
  changes_since: string;
  changes_window_days: number;
  shard_max_bytes: number;
  total_records: number;
  ecosystems: Record<string, ManifestEcosystem>;
};

type SnapshotRow = { name: string; versions?: string[]; modified: string };
type ChangeRow = { op: 'upsert' | 'delete'; modified: string; name: string };

type ClientState = {
  watermark: string;
  schema_version: string;
  updated_at: string;
};

type SyncMode = 'full' | 'none' | 'changes';

type EcosystemSync = {
  ecosystem: string;
  mode: SyncMode;
  shardCount: number;
  files: string[];
  downloadBytes: number;
  upserts: number;
  deletes: number;
  /** Rows the DB holds for this ecosystem after applying (from manifest). */
  records: number;
};

type InspectRow = {
  ecosystem: string;
  shards: number;
  records: number;
  allVersions: number;
  pinnedVersions: number;
  snapshotBytes: number;
  snapshotHashOk: boolean;
  changes: number;
  upserts: number;
  deletes: number;
  changesBytes: number;
  changesHashOk: boolean;
  oldestChange: string | null;
  newestChange: string | null;
};

type Args = {
  dir: string;
  stateFile: string;
  mode: 'inspect' | 'first' | 'next';
  since?: string;
  dryRun: boolean;
  json: boolean;
};

const SUPPORTED_SCHEMA_MAJOR = 2;

function parseArgs(): Args {
  const args = process.argv.slice(2);
  const value = (flag: string): string | undefined => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const first = args.includes('--first');
  const next = args.includes('--next');
  if (first && next) {
    console.error('Use either --first or --next, not both.');
    process.exit(2);
  }
  const since = value('--since');
  if (since && Number.isNaN(Date.parse(since))) {
    console.error(`--since must be an ISO timestamp, got "${since}"`);
    process.exit(2);
  }
  return {
    dir: resolve(value('--dir') ?? 'malicious-packages'),
    stateFile: resolve(value('--state') ?? '.client-state.json'),
    mode: first ? 'first' : next ? 'next' : 'inspect',
    since,
    dryRun: args.includes('--dry-run'),
    json: args.includes('--json'),
  };
}

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

function parseJsonl<T>(content: string): T[] {
  const rows: T[] = [];
  for (const line of content.split('\n')) {
    if (!line) continue;
    try {
      rows.push(JSON.parse(line) as T);
    } catch {
      /* skip malformed line */
    }
  }
  return rows;
}

function fmtBytes(n: number): string {
  if (n >= 1_048_576) return `${(n / 1_048_576).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function printTable(headers: string[], rows: string[][]): void {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  const line = (cells: string[]) => cells.map((c, i) => c.padEnd(widths[i])).join('  ');
  console.log(line(headers));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const r of rows) console.log(line(r));
}

/** Simulates `GET <file>` and verifies the body against the manifest hash. */
async function download(dir: string, file: string, expectedSha: string): Promise<string> {
  const text = await readFile(join(dir, file), 'utf-8');
  if (sha256(text) !== expectedSha) throw new Error(`${file}: sha256 does not match manifest`);
  return text;
}

async function loadManifest(dir: string): Promise<Manifest> {
  const manifest = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf-8')) as Manifest;
  const major = Number(manifest.schema_version.split('.')[0]);
  if (major !== SUPPORTED_SCHEMA_MAJOR) {
    throw new Error(`Unsupported schema_version ${manifest.schema_version}; this client understands ${SUPPORTED_SCHEMA_MAJOR}.x`);
  }
  if (!manifest.changes_since) throw new Error('manifest has no changes_since');
  for (const [eco, m] of Object.entries(manifest.ecosystems)) {
    if (!Array.isArray(m.files) || m.files.length === 0) throw new Error(`${eco}: manifest has no files[]`);
  }
  return manifest;
}

async function loadState(stateFile: string): Promise<ClientState | null> {
  try {
    return JSON.parse(await readFile(stateFile, 'utf-8')) as ClientState;
  } catch {
    return null;
  }
}

async function saveState(stateFile: string, manifest: Manifest): Promise<ClientState> {
  const state: ClientState = {
    watermark: manifest.generated_at,
    schema_version: manifest.schema_version,
    updated_at: new Date().toISOString(),
  };
  await writeFile(stateFile, JSON.stringify(state, null, 2) + '\n', 'utf-8');
  return state;
}

// ---------------------------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------------------------

async function inspect(dir: string, manifest: Manifest): Promise<InspectRow[]> {
  const rows: InspectRow[] = [];
  for (const [ecosystem, m] of Object.entries(manifest.ecosystems)) {
    let records = 0;
    let pinned = 0;
    let snapshotBytes = 0;
    let snapshotHashOk = true;
    for (const f of m.files) {
      const text = await readFile(join(dir, f.file), 'utf-8');
      const shardRows = parseJsonl<SnapshotRow>(text);
      records += shardRows.length;
      pinned += shardRows.filter((r) => Array.isArray(r.versions) && r.versions.length > 0).length;
      snapshotBytes += Buffer.byteLength(text, 'utf-8');
      if (sha256(text) !== f.sha256) snapshotHashOk = false;
    }
    const changesText = await readFile(join(dir, m.changes_file), 'utf-8');
    const ops = parseJsonl<ChangeRow>(changesText);
    const upserts = ops.filter((o) => o.op === 'upsert').length;
    rows.push({
      ecosystem,
      shards: m.files.length,
      records,
      allVersions: records - pinned,
      pinnedVersions: pinned,
      snapshotBytes,
      snapshotHashOk,
      changes: ops.length,
      upserts,
      deletes: ops.length - upserts,
      changesBytes: Buffer.byteLength(changesText, 'utf-8'),
      changesHashOk: sha256(changesText) === m.changes_sha256,
      newestChange: ops[0]?.modified ?? null,
      oldestChange: ops.length ? ops[ops.length - 1].modified : null,
    });
  }
  return rows;
}

// ---------------------------------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------------------------------

function decide(manifest: Manifest, watermark: string | null): SyncMode {
  if (watermark == null || watermark < manifest.changes_since) return 'full';
  if (watermark >= manifest.generated_at) return 'none';
  return 'changes';
}

/** FULL: every shard in files[]; stage all rows, upsert, delete rows not in staging. */
async function fullLoad(dir: string, ecosystem: string, m: ManifestEcosystem): Promise<EcosystemSync> {
  const files: string[] = [];
  let downloadBytes = 0;
  let upserts = 0;
  for (const f of m.files) {
    const text = await download(dir, f.file, f.sha256);
    files.push(f.file);
    downloadBytes += Buffer.byteLength(text, 'utf-8');
    upserts += parseJsonl<SnapshotRow>(text).length;
  }
  return { ecosystem, mode: 'full', shardCount: m.files.length, files, downloadBytes, upserts, deletes: 0, records: m.records };
}

/** CHANGES: read the changes file newest-first and stop at the first op already applied. */
async function applyChanges(dir: string, ecosystem: string, m: ManifestEcosystem, watermark: string): Promise<EcosystemSync> {
  const text = await download(dir, m.changes_file, m.changes_sha256);
  let upserts = 0;
  let deletes = 0;
  for (const line of text.split('\n')) {
    if (!line) continue;
    const op = JSON.parse(line) as ChangeRow;
    if (op.modified <= watermark) break;
    if (op.op === 'upsert') upserts++;
    else deletes++;
  }
  return {
    ecosystem,
    mode: 'changes',
    shardCount: m.files.length,
    files: [m.changes_file],
    downloadBytes: Buffer.byteLength(text, 'utf-8'),
    upserts,
    deletes,
    records: m.records,
  };
}

async function sync(dir: string, manifest: Manifest, watermark: string | null): Promise<{ mode: SyncMode; rows: EcosystemSync[] }> {
  const mode = decide(manifest, watermark);
  const rows: EcosystemSync[] = [];
  for (const [ecosystem, m] of Object.entries(manifest.ecosystems)) {
    if (mode === 'full') rows.push(await fullLoad(dir, ecosystem, m));
    else if (mode === 'changes') rows.push(await applyChanges(dir, ecosystem, m, watermark!));
    else rows.push({ ecosystem, mode: 'none', shardCount: m.files.length, files: [], downloadBytes: 0, upserts: 0, deletes: 0, records: m.records });
  }
  return { mode, rows };
}

function explain(manifest: Manifest, watermark: string | null, mode: SyncMode): string {
  if (mode === 'full') {
    return watermark == null
      ? 'FULL: no watermark (first load)'
      : `FULL: watermark ${watermark} < changes_since ${manifest.changes_since}`;
  }
  if (mode === 'none') return `NOTHING: watermark ${watermark} == generated_at ${manifest.generated_at}`;
  return `CHANGES: changes_since ${manifest.changes_since} <= watermark ${watermark} < generated_at ${manifest.generated_at}`;
}

function printSync(rows: EcosystemSync[]): void {
  printTable(
    ['ecosystem', 'shards', 'download files', 'download', 'upserts', 'deletes', 'rows after'],
    rows.map((r) => [
      r.ecosystem,
      String(r.shardCount),
      r.files.length ? r.files.join(', ') : '-',
      fmtBytes(r.downloadBytes),
      String(r.upserts),
      String(r.deletes),
      String(r.records),
    ])
  );
  const t = rows.reduce(
    (a, r) => ({ dl: a.dl + r.downloadBytes, up: a.up + r.upserts, del: a.del + r.deletes, rows: a.rows + r.records }),
    { dl: 0, up: 0, del: 0, rows: 0 }
  );
  console.log(`\nTotal: download ${fmtBytes(t.dl)} + manifest, apply ${t.up} upserts and ${t.del} deletes, ${t.rows} rows after sync`);
}

async function main(): Promise<void> {
  const args = parseArgs();
  const manifest = await loadManifest(args.dir);
  const header =
    `schema_version=${manifest.schema_version}  generated_at=${manifest.generated_at}  changes_since=${manifest.changes_since}  ` +
    `shard_max=${fmtBytes(manifest.shard_max_bytes)}  upstream=${manifest.upstream_commit?.slice(0, 12) ?? 'unknown'}`;

  if (args.mode === 'inspect') {
    const rows = await inspect(args.dir, manifest);
    const hashesOk = rows.every((r) => r.snapshotHashOk && r.changesHashOk);
    const totals = rows.reduce(
      (t, r) => ({
        shards: t.shards + r.shards,
        records: t.records + r.records,
        changes: t.changes + r.changes,
        upserts: t.upserts + r.upserts,
        deletes: t.deletes + r.deletes,
        snapshotBytes: t.snapshotBytes + r.snapshotBytes,
        changesBytes: t.changesBytes + r.changesBytes,
      }),
      { shards: 0, records: 0, changes: 0, upserts: 0, deletes: 0, snapshotBytes: 0, changesBytes: 0 }
    );
    if (args.json) {
      console.log(JSON.stringify({ mode: 'inspect', manifest: { ...manifest, ecosystems: undefined }, hashesOk, totals, ecosystems: rows }, null, 2));
      process.exit(hashesOk ? 0 : 1);
    }
    console.log(`Feed: ${args.dir}\n${header}\nhashes: ${hashesOk ? 'OK' : 'MISMATCH'}\n`);
    printTable(
      ['ecosystem', 'shards', 'full records', 'all-versions', 'pinned', 'snapshot', 'changes', 'upserts', 'deletes', 'changes file', 'oldest op', 'newest op'],
      rows.map((r) => [
        r.ecosystem,
        String(r.shards),
        String(r.records),
        String(r.allVersions),
        String(r.pinnedVersions),
        fmtBytes(r.snapshotBytes),
        String(r.changes),
        String(r.upserts),
        String(r.deletes),
        fmtBytes(r.changesBytes),
        r.oldestChange ?? '-',
        r.newestChange ?? '-',
      ])
    );
    console.log(
      `\nTotal: ${totals.records} full records in ${totals.shards} files (${fmtBytes(totals.snapshotBytes)}), ` +
        `${totals.changes} change ops (${totals.upserts} upserts, ${totals.deletes} deletes, ${fmtBytes(totals.changesBytes)})`
    );
    if (!hashesOk) process.exit(1);
    return;
  }

  let watermark: string | null = null;
  if (args.mode === 'next') {
    watermark = args.since ?? (await loadState(args.stateFile))?.watermark ?? null;
    if (!watermark) {
      console.error(`No state at ${args.stateFile} and no --since given. Run with --first for the initial load.`);
      process.exit(2);
    }
  }

  const { mode, rows } = await sync(args.dir, manifest, watermark);
  const saved = args.dryRun ? null : await saveState(args.stateFile, manifest);

  if (args.json) {
    console.log(JSON.stringify({ mode: args.mode, decision: mode, watermark, manifest: { ...manifest, ecosystems: undefined }, ecosystems: rows, state: saved }, null, 2));
    return;
  }

  console.log(`Feed: ${args.dir}\n${header}`);
  console.log(`Client: ${args.mode === 'first' ? '--first' : `--next (watermark ${watermark}${args.since ? ', from --since' : ''})`}`);
  console.log(`Decision: ${explain(manifest, watermark, mode)}\n`);
  printSync(rows);
  console.log(saved ? `\nState saved to ${args.stateFile} (watermark ${saved.watermark})` : '\nDry run: state not saved');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
