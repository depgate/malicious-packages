#!/usr/bin/env node
/**
 * Validate the generated feed: manifest parses, every listed file exists, hashes and record
 * counts match, snapshots are sorted by name, and every record carries `modified`.
 *
 * Run: npm run validate [-- --dir malicious]
 */
import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import { join, resolve } from 'path';

type ManifestEcosystem = {
  file: string;
  sha256: string;
  records: number;
  changes_file: string;
  changes_sha256: string;
  changes_records: number;
};

type Manifest = {
  schema_version: string;
  generated_at: string;
  total_records: number;
  ecosystems: Record<string, ManifestEcosystem>;
};

const args = process.argv.slice(2);
const dirIdx = args.indexOf('--dir');
const dir = resolve(dirIdx >= 0 && args[dirIdx + 1] ? args[dirIdx + 1] : 'malicious');

const errors: string[] = [];
const fail = (msg: string) => errors.push(msg);

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

function parseLines(content: string, file: string): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  const lines = content.split('\n');
  if (content.length && !content.endsWith('\n')) fail(`${file}: missing trailing newline`);
  for (const line of lines) {
    if (!line) continue;
    try {
      rows.push(JSON.parse(line) as Record<string, unknown>);
    } catch {
      fail(`${file}: malformed JSON line: ${line.slice(0, 80)}`);
    }
  }
  return rows;
}

async function main(): Promise<void> {
  const manifest = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf-8')) as Manifest;
  if (!/^\d+\.\d+\.\d+$/.test(manifest.schema_version)) fail(`bad schema_version ${manifest.schema_version}`);
  if (Number.isNaN(Date.parse(manifest.generated_at))) fail(`bad generated_at ${manifest.generated_at}`);

  let total = 0;
  for (const [eco, m] of Object.entries(manifest.ecosystems)) {
    const snapshotText = await readFile(join(dir, m.file), 'utf-8');
    if (sha256(snapshotText) !== m.sha256) fail(`${eco}: sha256 mismatch for ${m.file}`);
    const rows = parseLines(snapshotText, m.file);
    if (rows.length !== m.records) fail(`${eco}: ${m.file} has ${rows.length} records, manifest says ${m.records}`);
    total += rows.length;

    let prevName = '';
    for (const r of rows) {
      const name = r.name as string | undefined;
      if (!name) fail(`${eco}: record without name`);
      else if (name <= prevName) fail(`${eco}: ${m.file} not sorted/unique at ${name}`);
      if (typeof r.modified !== 'string' || Number.isNaN(Date.parse(r.modified))) {
        fail(`${eco}: ${name} has invalid modified`);
      }
      if (r.modified && (r.modified as string) > manifest.generated_at) {
        fail(`${eco}: ${name} modified is after generated_at`);
      }
      prevName = name ?? prevName;
    }

    const changesText = await readFile(join(dir, m.changes_file), 'utf-8');
    if (sha256(changesText) !== m.changes_sha256) fail(`${eco}: sha256 mismatch for ${m.changes_file}`);
    const ops = parseLines(changesText, m.changes_file);
    if (ops.length !== m.changes_records) {
      fail(`${eco}: ${m.changes_file} has ${ops.length} ops, manifest says ${m.changes_records}`);
    }
    let prevMod = '\uffff';
    for (const o of ops) {
      if (o.op !== 'upsert' && o.op !== 'delete') fail(`${eco}: bad op ${String(o.op)}`);
      if (typeof o.modified !== 'string' || o.modified > prevMod) {
        fail(`${eco}: ${m.changes_file} not newest-first at ${String(o.name)}`);
      }
      prevMod = o.modified as string;
    }
  }

  if (total !== manifest.total_records) fail(`total_records ${manifest.total_records} != ${total}`);
  if (total === 0) fail('feed is empty');

  if (errors.length) {
    for (const e of errors) console.error(`ERROR: ${e}`);
    process.exit(1);
  }
  console.log(`Validation passed: ${total} records across ${Object.keys(manifest.ecosystems).length} ecosystems`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
