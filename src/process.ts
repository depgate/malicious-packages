#!/usr/bin/env node
/**
 * Process OSSF malicious-packages into lightweight JSONL per ecosystem.
 * Uses git clone (no API). For local testing, use --limit N to process only first N packages per ecosystem.
 *
 * Run: npm run process           # full (CI)
 * Run: npm run process -- --limit 10   # local testing
 *
 * Requires: git (to clone the repo)
 */
import { mkdir, readdir, readFile, rm, writeFile } from 'fs/promises';
import { join } from 'path';
import { execSync } from 'child_process';

const OSSF_REPO = 'https://github.com/ossf/malicious-packages.git';
const OSSV_BASE = 'osv/malicious';
const OUTPUT_DIR = join(process.cwd(), 'malicious');

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
};

type OSVReport = {
  id?: string;
  summary?: string;
  affected?: OSVAffected[];
  withdrawn?: string;
};

type MalwareEntry = {
  name: string;
  versions?: string[];
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

function extractVersions(affected: OSVAffected[]): string[] | undefined {
  const versions = new Set<string>();
  for (const a of affected ?? []) {
    for (const range of a.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.introduced && ev.introduced !== '0') versions.add(ev.introduced);
        if (ev.fixed) versions.add(ev.fixed);
        if (ev.last_affected) versions.add(ev.last_affected);
      }
    }
  }
  if (versions.size === 0) return undefined;
  return [...versions];
}

function parseOSVReport(content: string): MalwareEntry | null {
  try {
    const data = JSON.parse(content) as OSVReport;
    if (data.withdrawn) return null;
    const aff = data.affected?.[0];
    const pkg = aff?.package;
    const name = pkg?.name;
    if (!name) return null;
    const versions = extractVersions(data.affected ?? []);
    return versions?.length ? { name, versions } : { name };
  } catch {
    return null;
  }
}

async function processEcosystem(
  repoPath: string,
  ecosystem: string,
  limit?: number
): Promise<MalwareEntry[]> {
  const basePath = join(repoPath, OSSV_BASE, ecosystem);
  const entries: MalwareEntry[] = [];
  const seen = new Set<string>();

  let dirs: string[];
  try {
    dirs = await readdir(basePath);
  } catch {
    return entries;
  }

  for (const pkgDir of dirs) {
    if (limit != null && entries.length >= limit) break;
    if (pkgDir.startsWith('.') || pkgDir === 'README.md') continue;
    const pkgPath = join(basePath, pkgDir);
    let files: string[];
    try {
      files = await readdir(pkgPath);
    } catch {
      continue;
    }
    const jsonFile = files.find((f) => f.endsWith('.json'));
    if (!jsonFile) continue;
    try {
      const content = await readFile(join(pkgPath, jsonFile), 'utf-8');
      const entry = parseOSVReport(content);
      if (entry && !seen.has(entry.name)) {
        seen.add(entry.name);
        entries.push(entry);
      }
    } catch {
      /* skip */
    }
  }

  return entries;
}

async function cloneRepo(repoPath: string): Promise<void> {
  execSync(`git clone --depth 1 ${OSSF_REPO} "${repoPath}"`, {
    stdio: 'inherit',
  });
}

async function writeJsonl(filePath: string, entries: MalwareEntry[]): Promise<void> {
  await mkdir(OUTPUT_DIR, { recursive: true });
  const lines = entries.map((e) => JSON.stringify(e)).join('\n') + (entries.length ? '\n' : '');
  await writeFile(filePath, lines, 'utf-8');
}

function parseArgs(): { limit?: number } {
  const args = process.argv.slice(2);
  const limitIdx = args.indexOf('--limit');
  const limit = limitIdx >= 0 && args[limitIdx + 1]
    ? parseInt(args[limitIdx + 1], 10)
    : undefined;
  return { limit: limit && limit > 0 ? limit : undefined };
}

async function main(): Promise<void> {
  const { limit } = parseArgs();
  const repoPath = join(process.cwd(), '.tmp-ossf-malicious-packages');

  if (limit) console.log(`Local mode: processing up to ${limit} packages per ecosystem`);
  console.log('Cloning OSSF malicious-packages...');
  try {
    await rm(repoPath, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  await cloneRepo(repoPath);

  try {
    await mkdir(OUTPUT_DIR, { recursive: true });
    let total = 0;

    for (const ecosystem of ECOSYSTEMS) {
      const entries = await processEcosystem(repoPath, ecosystem, limit);
      const outPath = join(OUTPUT_DIR, `${ecosystem.replace(':', '-')}.jsonl`);
      await writeJsonl(outPath, entries);
      console.log(`${ecosystem}: ${entries.length} packages -> ${outPath}`);
      total += entries.length;
    }

    console.log(`\nTotal: ${total} packages across ${ECOSYSTEMS.length} ecosystems`);
    console.log(`Output: ${OUTPUT_DIR}`);
  } finally {
    await rm(repoPath, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
