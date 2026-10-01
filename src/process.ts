#!/usr/bin/env node
/**
 * Process OSSF malicious-packages into lightweight, incrementally consumable JSONL per ecosystem.
 *
 * Outputs (in malicious/):
 *   <eco>.jsonl          full snapshot, sorted by name, one record per package
 *   <eco>.changes.jsonl  rolling window of upsert/delete ops, newest first
 *   manifest.json        schema version, run timestamp, upstream commit, per-file hashes
 *
 * The previously committed snapshot is used as state to compute what changed, so each run
 * only bumps `modified` on records whose content actually changed.
 *
 * Run: npm run process                     # full (CI)
 * Run: npm run process -- --limit 10       # local smoke test, writes to .tmp-malicious-output/
 * Flags: --out <dir> --repo <existing-clone-dir> --window-days <n> --force (skip mass-delete guard)
 *
 * Requires: git (to clone the repo)
 */
import { createHash } from 'crypto';
import { mkdir, readdir, readFile, rm, stat, writeFile } from 'fs/promises';
import { join, resolve } from 'path';
import { execSync } from 'child_process';

const OSSF_REPO = 'https://github.com/ossf/malicious-packages.git';
const OSSV_BASE = 'osv/malicious';
const SCHEMA_VERSION = '2.0.0';
const DEFAULT_WINDOW_DAYS = 180;
const MAX_DELETE_RATIO = 0.1;

type OSVRangeEvent = {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
};

type OSVRange = {
  type?: string;
  events?: OSVRangeEvent[];
};

type OSVAffected = {
  package?: { name?: string; ecosystem?: string };
  ranges?: OSVRange[];
  versions?: string[];
};

type OSVReport = {
  id?: string;
  published?: string;
  modified?: string;
  aliases?: string[];
  affected?: OSVAffected[];
  withdrawn?: string;
};

/** Snapshot record. Field order is significant: it is the on-disk order. */
export type MalwareEntry = {
  name: string;
  id?: string;
  aliases?: string[];
  /** Omitted means every version of the package is malicious. */
  versions?: string[];
  published?: string;
  /** Feed-level timestamp of the run in which this record last changed. */
  modified: string;
};

type ChangeOp =
  | ({ op: 'upsert'; modified: string } & Omit<MalwareEntry, 'modified'>)
  | { op: 'delete'; modified: string; name: string };

type Accumulator = {
  ids: string[];
  aliases: Set<string>;
  versions: Set<string>;
  allVersions: boolean;
  published?: string;
};

type EcosystemResult = {
  ecosystem: string;
  snapshot: MalwareEntry[];
  changes: ChangeOp[];
  added: number;
  updated: number;
  deleted: number;
  previousCount: number;
};

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
  upstream_repo: string;
  upstream_commit: string | null;
  changes_window_days: number;
  total_records: number;
  ecosystems: Record<string, ManifestEcosystem>;
};

const ECOSYSTEMS = [
  'npm',
  'pypi',
  'go',
  'maven',
  'nuget',
  'crates.io',
  'rubygems',
  'vscode',
  'vscode:open-vsx.org',
];

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Order MAL ids numerically (MAL-2022-3 < MAL-2022-10); anything else sorts lexically after. */
function compareMalIds(a: string, b: string): number {
  const re = /^MAL-(\d+)-(\d+)$/;
  const ma = re.exec(a);
  const mb = re.exec(b);
  if (ma && mb) {
    const ya = Number(ma[1]);
    const yb = Number(mb[1]);
    if (ya !== yb) return ya - yb;
    return Number(ma[2]) - Number(mb[2]);
  }
  if (ma) return -1;
  if (mb) return 1;
  return compareStrings(a, b);
}

function fileNameFor(ecosystem: string): string {
  return ecosystem.replace(':', '-');
}

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

/**
 * Fold one OSV report into the per-package accumulators. A report may list several
 * affected packages; each gets the report's metadata.
 */
function accumulateReport(content: string, acc: Map<string, Accumulator>): void {
  let data: OSVReport;
  try {
    data = JSON.parse(content) as OSVReport;
  } catch {
    return;
  }
  if (data.withdrawn) return;

  for (const affected of data.affected ?? []) {
    const name = affected.package?.name;
    if (!name) continue;

    let a = acc.get(name);
    if (!a) {
      a = { ids: [], aliases: new Set(), versions: new Set(), allVersions: false };
      acc.set(name, a);
    }

    if (data.id) a.ids.push(data.id);
    for (const alias of data.aliases ?? []) a.aliases.add(alias);
    if (data.published && (!a.published || data.published < a.published)) {
      a.published = data.published;
    }

    for (const v of affected.versions ?? []) a.versions.add(v);
    for (const range of affected.ranges ?? []) {
      const events = range.events ?? [];
      const bounded = events.some((ev) => ev.fixed || ev.last_affected);
      for (const ev of events) {
        if (ev.introduced === '0') {
          if (!bounded) a.allVersions = true;
        } else if (ev.introduced) {
          a.versions.add(ev.introduced);
        }
        if (ev.last_affected) a.versions.add(ev.last_affected);
      }
    }
  }
}

async function collectFromDir(
  dirPath: string,
  acc: Map<string, Accumulator>,
  limit?: number
): Promise<void> {
  if (limit != null && acc.size >= limit) return;

  let items;
  try {
    items = await readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const item of items) {
    if (limit != null && acc.size >= limit) break;
    if (item.name.startsWith('.') || item.name === 'README.md') continue;

    const fullPath = join(dirPath, item.name);
    if (item.isDirectory()) {
      await collectFromDir(fullPath, acc, limit);
    } else if (item.isFile() && item.name.endsWith('.json')) {
      try {
        accumulateReport(await readFile(fullPath, 'utf-8'), acc);
      } catch {
        /* skip unreadable file */
      }
    }
  }
}

/** Build the content part of a record (everything except `modified`), with stable field order. */
function toContent(name: string, a: Accumulator): Omit<MalwareEntry, 'modified'> {
  const entry: Omit<MalwareEntry, 'modified'> = { name };
  const ids = [...new Set(a.ids)].sort(compareMalIds);
  if (ids.length) {
    entry.id = ids[0];
    for (const other of ids.slice(1)) a.aliases.add(other);
  }
  if (a.aliases.size) entry.aliases = [...a.aliases].sort(compareStrings);
  if (!a.allVersions && a.versions.size) entry.versions = [...a.versions].sort(compareStrings);
  if (a.published) entry.published = a.published;
  return entry;
}

/** Canonical key used to decide whether a record's content changed between runs. */
function contentKey(e: Omit<MalwareEntry, 'modified'>): string {
  return JSON.stringify([e.name, e.id ?? null, e.aliases ?? null, e.versions ?? null, e.published ?? null]);
}

async function readJsonl<T>(filePath: string): Promise<T[]> {
  let content: string;
  try {
    content = await readFile(filePath, 'utf-8');
  } catch {
    return [];
  }
  const out: T[] = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as T);
    } catch {
      /* skip malformed line */
    }
  }
  return out;
}

function toJsonl(rows: unknown[]): string {
  return rows.length ? rows.map((r) => JSON.stringify(r)).join('\n') + '\n' : '';
}

function compareOps(a: ChangeOp, b: ChangeOp): number {
  return compareStrings(b.modified, a.modified) || compareStrings(a.name, b.name);
}

async function processEcosystem(
  repoPath: string,
  ecosystem: string,
  outDir: string,
  runTs: string,
  windowDays: number,
  limit?: number
): Promise<EcosystemResult> {
  const acc = new Map<string, Accumulator>();
  await collectFromDir(join(repoPath, OSSV_BASE, ecosystem), acc, limit);

  const base = fileNameFor(ecosystem);
  const previous = await readJsonl<Partial<MalwareEntry> & { name: string }>(join(outDir, `${base}.jsonl`));
  const previousByName = new Map(previous.map((p) => [p.name, p]));
  // A snapshot written by the pre-2.0 producer has no `modified` field. Its records are
  // treated as pre-existing: they get stamped with this run's timestamp but are not
  // emitted as change ops, so the changes file is not flooded on the first run.
  const legacyBootstrap = previous.length > 0 && previous.every((p) => !p.modified);

  const snapshot: MalwareEntry[] = [];
  const ops: ChangeOp[] = [];
  let added = 0;
  let updated = 0;

  const names = [...acc.keys()].sort(compareStrings);
  for (const name of names) {
    const content = toContent(name, acc.get(name)!);
    const prev = previousByName.get(name);
    let modified: string;
    if (!prev) {
      modified = runTs;
      added++;
      ops.push({ op: 'upsert', modified, ...content });
    } else if (legacyBootstrap) {
      modified = runTs;
    } else if (prev.modified && contentKey(prev as MalwareEntry) === contentKey(content)) {
      modified = prev.modified;
    } else {
      modified = runTs;
      updated++;
      ops.push({ op: 'upsert', modified, ...content });
    }
    snapshot.push({ ...content, modified });
  }

  let deleted = 0;
  for (const prev of previous) {
    if (!acc.has(prev.name)) {
      deleted++;
      ops.push({ op: 'delete', modified: runTs, name: prev.name });
    }
  }

  const cutoff = new Date(Date.parse(runTs) - windowDays * 86_400_000).toISOString();
  const touched = new Set(ops.map((o) => o.name));
  const existingOps = await readJsonl<ChangeOp>(join(outDir, `${base}.changes.jsonl`));
  const changes = existingOps
    .filter((o) => !touched.has(o.name) && o.modified >= cutoff)
    .concat(ops)
    .sort(compareOps);

  return { ecosystem, snapshot, changes, added, updated, deleted, previousCount: previous.length };
}

function revParse(repoPath: string): string | null {
  try {
    return execSync('git rev-parse HEAD', { cwd: repoPath, encoding: 'utf-8' }).trim();
  } catch {
    return null;
  }
}

function cloneRepo(repoPath: string): string | null {
  execSync(`git clone --quiet --depth 1 ${OSSF_REPO} "${repoPath}"`, { stdio: 'inherit' });
  return revParse(repoPath);
}

function parseArgs(): {
  limit?: number;
  out?: string;
  repo?: string;
  windowDays: number;
  force: boolean;
} {
  const args = process.argv.slice(2);
  const value = (flag: string): string | undefined => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const limitRaw = parseInt(value('--limit') ?? '', 10);
  const windowRaw = parseInt(value('--window-days') ?? '', 10);
  return {
    limit: limitRaw > 0 ? limitRaw : undefined,
    out: value('--out'),
    repo: value('--repo'),
    windowDays: windowRaw > 0 ? windowRaw : DEFAULT_WINDOW_DAYS,
    force: args.includes('--force'),
  };
}

async function main(): Promise<void> {
  const { limit, out, repo, windowDays, force } = parseArgs();
  // Limited runs produce bogus deletes against the real snapshot, so they default to a scratch dir.
  const outDir = resolve(out ?? (limit ? '.tmp-malicious-output' : 'malicious'));
  const repoPath = resolve(repo ?? '.tmp-ossf-malicious-packages');
  const runTs = nowIso();

  if (limit) console.log(`Local mode: processing up to ${limit} packages per ecosystem -> ${outDir}`);
  let upstreamCommit: string | null = null;
  if (repo) {
    console.log(`Using existing upstream clone at ${repoPath}`);
    upstreamCommit = revParse(repoPath);
  } else {
    console.log('Cloning OSSF malicious-packages...');
    await rm(repoPath, { recursive: true, force: true });
    upstreamCommit = cloneRepo(repoPath);
  }

  try {
    await mkdir(outDir, { recursive: true });

    const results: EcosystemResult[] = [];
    for (const ecosystem of ECOSYSTEMS) {
      const r = await processEcosystem(repoPath, ecosystem, outDir, runTs, windowDays, limit);
      results.push(r);
      console.log(
        `${ecosystem}: ${r.snapshot.length} packages (+${r.added} ~${r.updated} -${r.deleted}), ` +
          `${r.changes.length} ops in window`
      );
    }

    const total = results.reduce((n, r) => n + r.snapshot.length, 0);
    if (total === 0) throw new Error('No packages produced from upstream clone; aborting without writing.');

    for (const r of results) {
      if (r.previousCount > 0 && r.deleted / r.previousCount > MAX_DELETE_RATIO) {
        const msg =
          `${r.ecosystem}: ${r.deleted} of ${r.previousCount} previous records would be deleted ` +
          `(> ${MAX_DELETE_RATIO * 100}%). Likely a bad upstream fetch.`;
        if (!force) throw new Error(`${msg} Re-run with --force to override.`);
        console.warn(`WARNING: ${msg} Proceeding because --force was given.`);
      }
    }

    const manifest: Manifest = {
      schema_version: SCHEMA_VERSION,
      generated_at: runTs,
      upstream_repo: OSSF_REPO,
      upstream_commit: upstreamCommit,
      changes_window_days: windowDays,
      total_records: total,
      ecosystems: {},
    };

    for (const r of results) {
      const base = fileNameFor(r.ecosystem);
      const snapshotText = toJsonl(r.snapshot);
      const changesText = toJsonl(r.changes);
      await writeFile(join(outDir, `${base}.jsonl`), snapshotText, 'utf-8');
      await writeFile(join(outDir, `${base}.changes.jsonl`), changesText, 'utf-8');
      const { size } = await stat(join(outDir, `${base}.jsonl`));
      manifest.ecosystems[r.ecosystem] = {
        file: `${base}.jsonl`,
        sha256: sha256(snapshotText),
        bytes: size,
        records: r.snapshot.length,
        changes_file: `${base}.changes.jsonl`,
        changes_sha256: sha256(changesText),
        changes_records: r.changes.length,
        max_modified: r.snapshot.reduce<string | null>(
          (m, e) => (m == null || e.modified > m ? e.modified : m),
          null
        ),
      };
    }

    await writeFile(join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf-8');

    console.log(`\nTotal: ${total} packages across ${ECOSYSTEMS.length} ecosystems`);
    console.log(`Upstream commit: ${upstreamCommit ?? 'unknown'}`);
    console.log(`Output: ${outDir}`);
  } finally {
    if (!repo) await rm(repoPath, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
