#!/usr/bin/env node
/**
 * Reference client for the malicious-packages feed.
 *
 * Modes:
 *   (default)  inspect: per ecosystem, how many full records and change ops exist, hash status
 *   --first    first-time load: read manifest + every <eco>.jsonl, count records, save state
 *   --next     subsequent sync: read manifest, decide per ecosystem (none / changes / full),
 *              count what would be applied, save state
 *
 * The client keeps one small state file (default .client-state.json) holding the last applied
 * manifest `generated_at` (the watermark) and per-file sha256 values. No database is involved;
 * "apply" is simulated and reported as counts per ecosystem.
 *
 * Run: npm run client
 *      npm run client -- --first
 *      npm run client -- --next
 *      npm run client -- --next --since 2026-09-27T03:23:00Z   # override stored watermark
 * Flags: --dir <feed dir> --state <file> --dry-run (do not save state) --json
 */
import { createHash } from 'crypto';
import { readFile, writeFile } from 'fs/promises';
import { join, resolve } from 'path';

type ManifestEcosystem = {
  file: string;
  sha256: string;
  bytes: number;
  records: number;
  changes_file: string;
  changes_sha256: string;
  changes_records: number;
  max_modified: string | null;
};

type Manifest = {
  schema_version: string;
  generated_at: string;
  upstream_commit: string | null;
  changes_window_days: number;
  total_records: number;
  ecosystems: Record<string, ManifestEcosystem>;
};

type SnapshotRow = { name: string; versions?: string[]; modified: string };
type ChangeRow = { op: 'upsert' | 'delete'; modified: string; name: string };

type ClientState = {
  watermark: string;
  schema_version: string;
  hashes: Record<string, string>;
  updated_at: string;
};

type SyncMode = 'none' | 'skip' | 'changes' | 'full';

type EcosystemSync = {
  ecosystem: string;
  mode: SyncMode;
  reason: string;
  file: string | null;
  downloadBytes: number;
  upserts: number;
  deletes: number;
  /** Rows the DB would hold for this ecosystem after applying (from manifest). */
  records: number;
};

type InspectRow = {
  ecosystem: string;
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
    dir: resolve(value('--dir') ?? 'malicious'),
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

/** Simulates `GET <file>`: returns the content and verifies it against the manifest hash. */
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
    hashes: Object.fromEntries(Object.entries(manifest.ecosystems).map(([eco, m]) => [eco, m.sha256])),
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
    const snapshotText = await readFile(join(dir, m.file), 'utf-8');
    const changesText = await readFile(join(dir, m.changes_file), 'utf-8');
    const records = parseJsonl<SnapshotRow>(snapshotText);
    const ops = parseJsonl<ChangeRow>(changesText);
    const pinned = records.filter((r) => Array.isArray(r.versions) && r.versions.length > 0).length;
    const upserts = ops.filter((o) => o.op === 'upsert').length;
    rows.push({
      ecosystem,
      records: records.length,
      allVersions: records.length - pinned,
      pinnedVersions: pinned,
      snapshotBytes: Buffer.byteLength(snapshotText, 'utf-8'),
      snapshotHashOk: sha256(snapshotText) === m.sha256,
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
// --first: full load of every ecosystem
// ---------------------------------------------------------------------------------------------

async function firstLoad(dir: string, manifest: Manifest): Promise<EcosystemSync[]> {
  const out: EcosystemSync[] = [];
  for (const [ecosystem, m] of Object.entries(manifest.ecosystems)) {
    const text = await download(dir, m.file, m.sha256);
    const records = parseJsonl<SnapshotRow>(text);
    out.push({
      ecosystem,
      mode: 'full',
      reason: 'no watermark',
      file: m.file,
      downloadBytes: Buffer.byteLength(text, 'utf-8'),
      upserts: records.length,
      deletes: 0,
      records: m.records,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// --next: decide per ecosystem which file to use, following the README logic table
// ---------------------------------------------------------------------------------------------

async function nextSync(
  dir: string,
  manifest: Manifest,
  watermark: string,
  knownHashes: Record<string, string>
): Promise<EcosystemSync[]> {
  const out: EcosystemSync[] = [];
  const windowMs = manifest.changes_window_days * 86_400_000;
  const gapMs = Date.parse(manifest.generated_at) - Date.parse(watermark);
  const feedUnchanged = watermark >= manifest.generated_at;

  for (const [ecosystem, m] of Object.entries(manifest.ecosystems)) {
    const base = { ecosystem, records: m.records };

    if (feedUnchanged) {
      out.push({ ...base, mode: 'none', reason: 'generated_at == watermark', file: null, downloadBytes: 0, upserts: 0, deletes: 0 });
      continue;
    }
    if (knownHashes[ecosystem] === m.sha256) {
      out.push({ ...base, mode: 'skip', reason: 'snapshot sha256 unchanged', file: null, downloadBytes: 0, upserts: 0, deletes: 0 });
      continue;
    }
    if (gapMs > windowMs) {
      const text = await download(dir, m.file, m.sha256);
      const records = parseJsonl<SnapshotRow>(text);
      out.push({
        ...base,
        mode: 'full',
        reason: `gap ${Math.round(gapMs / 86_400_000)}d > window ${manifest.changes_window_days}d`,
        file: m.file,
        downloadBytes: Buffer.byteLength(text, 'utf-8'),
        upserts: records.length,
        deletes: 0,
      });
      continue;
    }

    const text = await download(dir, m.changes_file, m.changes_sha256);
    let upserts = 0;
    let deletes = 0;
    // Newest first: stop at the first op the client has already applied.
    for (const line of text.split('\n')) {
      if (!line) continue;
      const op = JSON.parse(line) as ChangeRow;
      if (op.modified <= watermark) break;
      if (op.op === 'upsert') upserts++;
      else deletes++;
    }
    out.push({
      ...base,
      mode: 'changes',
      reason: `gap ${Math.round(gapMs / 86_400_000)}d within window`,
      file: m.changes_file,
      downloadBytes: Buffer.byteLength(text, 'utf-8'),
      upserts,
      deletes,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------

function printSync(title: string, rows: EcosystemSync[]): void {
  console.log(title);
  printTable(
    ['ecosystem', 'mode', 'file', 'download', 'upserts', 'deletes', 'rows after', 'reason'],
    rows.map((r) => [
      r.ecosystem,
      r.mode,
      r.file ?? '-',
      fmtBytes(r.downloadBytes),
      String(r.upserts),
      String(r.deletes),
      String(r.records),
      r.reason,
    ])
  );
  const t = rows.reduce(
    (a, r) => ({ dl: a.dl + r.downloadBytes, up: a.up + r.upserts, del: a.del + r.deletes, rows: a.rows + r.records }),
    { dl: 0, up: 0, del: 0, rows: 0 }
  );
  const byMode = rows.reduce<Record<string, number>>((a, r) => ({ ...a, [r.mode]: (a[r.mode] ?? 0) + 1 }), {});
  console.log(
    `\nTotal: download ${fmtBytes(t.dl)} + manifest, apply ${t.up} upserts and ${t.del} deletes, ` +
      `${t.rows} rows after sync. Modes: ${Object.entries(byMode).map(([k, v]) => `${k}=${v}`).join(', ')}`
  );
}

async function main(): Promise<void> {
  const args = parseArgs();
  const manifest = await loadManifest(args.dir);
  const header = `schema_version=${manifest.schema_version}  generated_at=${manifest.generated_at}  window=${manifest.changes_window_days}d  upstream=${manifest.upstream_commit?.slice(0, 12) ?? 'unknown'}`;

  if (args.mode === 'inspect') {
    const rows = await inspect(args.dir, manifest);
    const hashesOk = rows.every((r) => r.snapshotHashOk && r.changesHashOk);
    const totals = rows.reduce(
      (t, r) => ({
        records: t.records + r.records,
        changes: t.changes + r.changes,
        upserts: t.upserts + r.upserts,
        deletes: t.deletes + r.deletes,
        snapshotBytes: t.snapshotBytes + r.snapshotBytes,
        changesBytes: t.changesBytes + r.changesBytes,
      }),
      { records: 0, changes: 0, upserts: 0, deletes: 0, snapshotBytes: 0, changesBytes: 0 }
    );
    if (args.json) {
      console.log(JSON.stringify({ mode: 'inspect', manifest: { ...manifest, ecosystems: undefined }, hashesOk, totals, ecosystems: rows }, null, 2));
      process.exit(hashesOk ? 0 : 1);
    }
    console.log(`Feed: ${args.dir}\n${header}\nhashes: ${hashesOk ? 'OK' : 'MISMATCH'}\n`);
    printTable(
      ['ecosystem', 'full records', 'all-versions', 'pinned', 'snapshot', 'changes', 'upserts', 'deletes', 'changes file', 'oldest op', 'newest op'],
      rows.map((r) => [
        r.ecosystem,
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
    console.log(`\nTotal: ${totals.records} full records (${fmtBytes(totals.snapshotBytes)}), ${totals.changes} change ops (${totals.upserts} upserts, ${totals.deletes} deletes, ${fmtBytes(totals.changesBytes)})`);
    if (!hashesOk) process.exit(1);
    return;
  }

  let rows: EcosystemSync[];
  let watermark: string | null = null;
  let hashes: Record<string, string> = {};

  if (args.mode === 'first') {
    rows = await firstLoad(args.dir, manifest);
  } else {
    const state = await loadState(args.stateFile);
    watermark = args.since ?? state?.watermark ?? null;
    if (!watermark) {
      console.error(`No state at ${args.stateFile} and no --since given. Run with --first for the initial load.`);
      process.exit(2);
    }
    hashes = args.since ? {} : state?.hashes ?? {};
    rows = await nextSync(args.dir, manifest, watermark, hashes);
  }

  const saved = args.dryRun ? null : await saveState(args.stateFile, manifest);

  if (args.json) {
    console.log(JSON.stringify({ mode: args.mode, manifest: { ...manifest, ecosystems: undefined }, watermark, ecosystems: rows, state: saved }, null, 2));
    return;
  }

  console.log(`Feed: ${args.dir}\n${header}`);
  if (args.mode === 'first') {
    console.log('Mode: --first (no watermark, full load of every ecosystem)\n');
    printSync('First load:', rows);
  } else {
    console.log(`Mode: --next (watermark ${watermark}${args.since ? ', from --since' : ''})\n`);
    printSync('Next sync:', rows);
  }
  console.log(saved ? `\nState saved to ${args.stateFile} (watermark ${saved.watermark})` : '\nDry run: state not saved');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
