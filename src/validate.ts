#!/usr/bin/env node
/**
 * Validate the generated feed: manifest parses, every listed shard exists, hashes, byte sizes and
 * record counts match, names are sorted and unique across shards, shard name ranges are correct,
 * every record carries `modified`, changes files are newest-first, and no file is large enough
 * to trip GitHub's size limits.
 *
 * Run: npm run validate [-- --dir malicious-packages]
 */
import { createHash } from 'crypto';
import { readdir, readFile } from 'fs/promises';
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
};

type Manifest = {
  schema_version: string;
  generated_at: string;
  changes_since: string;
  shard_max_bytes: number;
  total_records: number;
  ecosystems: Record<string, ManifestEcosystem>;
};

/** GitHub warns on push above 50 MB and rejects above 100 MB; fail well before the hard limit. */
const GITHUB_FILE_LIMIT_BYTES = 50 * 1024 * 1024;

const args = process.argv.slice(2);
const dirIdx = args.indexOf('--dir');
const dir = resolve(dirIdx >= 0 && args[dirIdx + 1] ? args[dirIdx + 1] : 'malicious-packages');

const errors: string[] = [];
const fail = (msg: string) => errors.push(msg);

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

function parseLines(content: string, file: string): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  if (content.length && !content.endsWith('\n')) fail(`${file}: missing trailing newline`);
  for (const line of content.split('\n')) {
    if (!line) continue;
    try {
      rows.push(JSON.parse(line) as Record<string, unknown>);
    } catch {
      fail(`${file}: malformed JSON line: ${line.slice(0, 80)}`);
    }
  }
  return rows;
}

async function readChecked(m: { file: string; sha256: string; bytes: number }, label: string): Promise<string> {
  const text = await readFile(join(dir, m.file), 'utf-8');
  if (sha256(text) !== m.sha256) fail(`${label}: sha256 mismatch for ${m.file}`);
  const bytes = Buffer.byteLength(text, 'utf-8');
  if (bytes !== m.bytes) fail(`${label}: ${m.file} is ${bytes} bytes, manifest says ${m.bytes}`);
  if (bytes > GITHUB_FILE_LIMIT_BYTES) fail(`${label}: ${m.file} is ${bytes} bytes, above the ${GITHUB_FILE_LIMIT_BYTES} byte GitHub limit`);
  return text;
}

async function main(): Promise<void> {
  const manifest = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf-8')) as Manifest;
  if (!/^\d+\.\d+\.\d+$/.test(manifest.schema_version)) fail(`bad schema_version ${manifest.schema_version}`);
  if (Number.isNaN(Date.parse(manifest.generated_at))) fail(`bad generated_at ${manifest.generated_at}`);
  if (Number.isNaN(Date.parse(manifest.changes_since))) fail(`bad changes_since ${manifest.changes_since}`);
  else if (manifest.changes_since > manifest.generated_at) fail('changes_since is after generated_at');
  if (!(manifest.shard_max_bytes > 0)) fail(`bad shard_max_bytes ${manifest.shard_max_bytes}`);

  const listed = new Set<string>(['manifest.json']);
  let total = 0;

  for (const [eco, m] of Object.entries(manifest.ecosystems)) {
    if (!Array.isArray(m.files) || m.files.length === 0) {
      fail(`${eco}: manifest has no files[]`);
      continue;
    }

    let ecoRecords = 0;
    let ecoBytes = 0;
    let prevName = '';
    for (const f of m.files) {
      listed.add(f.file);
      const text = await readChecked(f, eco);
      const rows = parseLines(text, f.file);
      if (rows.length !== f.records) fail(`${eco}: ${f.file} has ${rows.length} records, manifest says ${f.records}`);
      if (f.bytes > manifest.shard_max_bytes && rows.length > 1) {
        fail(`${eco}: ${f.file} is ${f.bytes} bytes, above shard_max_bytes ${manifest.shard_max_bytes}`);
      }
      ecoRecords += rows.length;
      ecoBytes += f.bytes;

      for (const r of rows) {
        const name = r.name as string | undefined;
        if (!name) fail(`${eco}: ${f.file} has a record without name`);
        else if (name <= prevName) fail(`${eco}: ${f.file} not sorted/unique across shards at ${name}`);
        if (typeof r.modified !== 'string' || Number.isNaN(Date.parse(r.modified))) {
          fail(`${eco}: ${name} has invalid modified`);
        } else if (r.modified > manifest.generated_at) {
          fail(`${eco}: ${name} modified is after generated_at`);
        }
        prevName = name ?? prevName;
      }
    }
    if (ecoRecords !== m.records) fail(`${eco}: shards hold ${ecoRecords} records, manifest says ${m.records}`);
    if (ecoBytes !== m.bytes) fail(`${eco}: shards total ${ecoBytes} bytes, manifest says ${m.bytes}`);
    total += ecoRecords;

    listed.add(m.changes_file);
    const changesText = await readChecked(
      { file: m.changes_file, sha256: m.changes_sha256, bytes: m.changes_bytes },
      eco
    );
    const ops = parseLines(changesText, m.changes_file);
    if (ops.length !== m.changes_records) {
      fail(`${eco}: ${m.changes_file} has ${ops.length} ops, manifest says ${m.changes_records}`);
    }
    let prevMod = '\uffff';
    const seen = new Set<string>();
    for (const o of ops) {
      if (o.op !== 'upsert' && o.op !== 'delete') fail(`${eco}: bad op ${String(o.op)}`);
      if (typeof o.modified !== 'string' || o.modified > prevMod) {
        fail(`${eco}: ${m.changes_file} not newest-first at ${String(o.name)}`);
      } else if (o.modified < manifest.changes_since) {
        fail(`${eco}: ${m.changes_file} has op for ${String(o.name)} older than changes_since`);
      }
      if (seen.has(o.name as string)) fail(`${eco}: ${m.changes_file} has duplicate op for ${String(o.name)}`);
      seen.add(o.name as string);
      prevMod = o.modified as string;
    }
  }

  for (const name of await readdir(dir)) {
    if (name.endsWith('.jsonl') && !listed.has(name)) fail(`stray file not listed in manifest: ${name}`);
  }

  if (total !== manifest.total_records) fail(`total_records ${manifest.total_records} != ${total}`);
  if (total === 0) fail('feed is empty');

  if (errors.length) {
    for (const e of errors) console.error(`ERROR: ${e}`);
    process.exit(1);
  }
  const shards = Object.values(manifest.ecosystems).reduce((n, m) => n + m.files.length, 0);
  console.log(`Validation passed: ${total} records, ${shards} snapshot files across ${Object.keys(manifest.ecosystems).length} ecosystems`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
