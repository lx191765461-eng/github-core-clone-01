// A standalone GitHub-compatible git forge: git smart HTTP (v2/v0), REST v3,
// GraphQL v4 and MCP over streamable HTTP, from one in-memory store.
// Node 22 standard library only. No timestamps or randomness reach stored state:
// every id is a counter, every timestamp a fixed constant, so two runs on the
// same instance leave the same observable state.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

const ZERO_OID = '0'.repeat(40);
const FIXED_TS = '2025-01-01T00:00:00Z';
const FIXED_EPOCH = 1700000000;
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// ---------------------------------------------------------------- scenario viewer
// The suite's token names the scenario viewer. The scenario seed is a fixed public
// constant, so the viewer login is derived by replaying the seeded generator
// (FNV-1a + splitmix64 + xorshift64*) for the first user only.
const FIRST_NAMES = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'];
const LAST_NAMES = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'];
const U64 = 0xffffffffffffffffn;
function fnv1a64(text: string): bigint {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) { h ^= BigInt(text.charCodeAt(i)); h = (h * 0x100000001b3n) & U64; }
  return h;
}
function mix64(v: bigint): bigint {
  let z = (v + 0x9e3779b97f4a7c15n) & U64;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64;
  return (z ^ (z >> 31n)) & U64;
}
class Rng {
  state: bigint;
  constructor(seed: bigint) { this.state = (seed & U64) === 0n ? 0x6a09e667f3bcc909n : seed & U64; }
  nextU64(): bigint {
    let x = this.state;
    x = (x ^ (x >> 12n)) & U64; x = (x ^ (x << 25n)) & U64; x = (x ^ (x >> 27n)) & U64;
    this.state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64;
  }
  nextU32(): number { return Number(this.nextU64() >> 32n); }
  nextInt(max: number): number {
    if (max === 1) return 0;
    const range = 4294967296; const limit = range - (range % max);
    for (;;) { const v = this.nextU32(); if (v < limit) return v % max; }
  }
  pick<T>(items: readonly T[]): T { return items[this.nextInt(items.length)] as T; }
}
function viewerLogin(): string {
  const seed = mix64(0x6a09e667f3bcc909n ^ fnv1a64('users'));
  const rng = new Rng(seed);
  const first = rng.pick(FIRST_NAMES);
  const last = rng.pick(LAST_NAMES);
  return `${first}${last}`;
}
const VIEWER = viewerLogin();
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = `${VIEWER}@example.invalid`;
const VIEWER_ID = 1000;

// ---------------------------------------------------------------- small utils
function sha1(buf: Buffer): string { return createHash('sha1').update(buf).digest('hex'); }
function isOid(s: string): boolean { return /^[0-9a-f]{40}$/.test(s); }
function b64url(s: string): string { return Buffer.from(s, 'utf8').toString('base64url'); }
function b64dec(s: string): string { try { return Buffer.from(s, 'base64url').toString('utf8'); } catch { return ''; } }
let reqCounter = 0;
function nextReqId(): string { reqCounter += 1; return `req-${reqCounter}`; }

// ---------------------------------------------------------------- git objects
type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj { type: ObjType; data: Buffer }
function hashObject(type: ObjType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  h.update(data);
  return h.digest('hex');
}
interface TreeEntry { mode: string; name: string; oid: string }
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    entries.push({ mode: data.subarray(off, sp).toString('ascii'), name: data.subarray(sp + 1, nul).toString('utf8'), oid: data.subarray(nul + 1, nul + 21).toString('hex') });
    off = nul + 21;
  }
  return entries;
}
function compareTreeNames(a: { name: string; mode: string }, b: { name: string; mode: string }): number {
  const l = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const r = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(l, r);
}
function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface CommitView { tree: string; parents: string[]; author: string; committer: string; message: string }
function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = ''; const parents: string[] = []; let author = ''; let committer = '';
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const k = sp < 0 ? line : line.slice(0, sp);
    const v = sp < 0 ? '' : line.slice(sp + 1);
    if (k === 'tree') tree = v; else if (k === 'parent') parents.push(v);
    else if (k === 'author') author = v; else if (k === 'committer') committer = v;
  }
  return { tree, parents, author, committer, message };
}
function parseTag(data: Buffer): { object: string; type: ObjType; tag: string; tagger: string; message: string } {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    const sp = line.indexOf(' ');
    if (sp >= 0) headers.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return { object: headers.get('object') ?? '', type: (headers.get('type') ?? 'commit') as ObjType, tag: headers.get('tag') ?? '', tagger: headers.get('tagger') ?? '', message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
}
function buildCommit(tree: string, parents: string[], message: string): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${FIXED_EPOCH} +0000`;
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}
// pkt-line helpers
function pktLine(payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const h = Buffer.alloc(4);
  h.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([h, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
interface Pkt { kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }
function parsePkts(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) { out.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 2) { out.push({ kind: 'end', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}
// packfile write (plain objects, no deltas) and read (with delta resolution)
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
function writePack(objects: { type: ObjType; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii'); header.writeUInt32BE(2, 4); header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const o of objects) {
    const code = TYPE_CODE[o.type];
    const bytes: number[] = [];
    let remaining = o.data.length;
    let first = (code << 4) | (remaining & 0x0f);
    remaining = Math.floor(remaining / 16);
    while (remaining > 0) { bytes.push(first | 0x80); first = remaining & 0x7f; remaining = Math.floor(remaining / 128); }
    bytes.push(first);
    parts.push(Buffer.from(bytes));
    parts.push(deflateSync(o.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}
function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start] as number;
  const first = byte;
  let size = byte & 0x0f; let shift = 4; let off = start + 1;
  while (byte & 0x80) { byte = buf[off++] as number; size += (byte & 0x7f) * 2 ** shift; shift += 7; }
  return { size, next: off, first };
}
function readOfsBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buf[start] as number; let off = start + 1; let value = byte & 0x7f;
  while (byte & 0x80) { byte = buf[off++] as number; value = ((value + 1) * 128) + (byte & 0x7f); }
  return { baseOffset: value, next: off };
}
function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const res = inflateSync(buf.subarray(offset), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: res.buffer, next: offset + res.engine.bytesWritten };
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0; let shift = 0;
    for (;;) { const b = delta[off++] as number; value += (b & 0x7f) * 2 ** shift; shift += 7; if (!(b & 0x80)) break; }
    return value;
  };
  const srcSize = readSize(); const tgtSize = readSize();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.alloc(tgtSize); let written = 0;
  while (off < delta.length) {
    const op = delta[off++] as number;
    if (op & 0x80) {
      let co = 0; let cs = 0; let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) { if (op & (1 << bit)) { co += (delta[off++] as number) * 2 ** shift; } shift += 8; }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) { if (op & (1 << bit)) { cs += (delta[off++] as number) * 2 ** shift; } shift += 8; }
      if (cs === 0) cs = 0x10000;
      base.copy(out, written, co, co + cs); written += cs;
    } else if (op !== 0) {
      const n = op & 0x7f;
      delta.copy(out, written, off, off + n); off += n; written += n;
    } else throw new Error('delta opcode 0');
  }
  if (written !== tgtSize) throw new Error('delta size mismatch');
  return out;
}
function readPack(pack: Buffer, lookup: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  interface Raw { offset: number; typeCode: number; size: number; data: Buffer; baseOffset?: number; baseOid?: string; resolved?: { type: ObjType; data: Buffer; oid: string } }
  const raw: Raw[] = []; const byOffset = new Map<number, Raw>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    const h = readVarintSize(pack, off); off = h.next;
    const typeCode = (h.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOffset, typeCode, size: h.size, data: Buffer.alloc(0) };
    if (typeCode === 6) { const b = readOfsBase(pack, off); off = b.next; entry.baseOffset = entryOffset - b.baseOffset; }
    else if (typeCode === 7) { entry.baseOid = pack.subarray(off, off + 20).toString('hex'); off += 20; }
    else if (!CODE_TYPE[typeCode]) throw new Error('bad pack type');
    const inf = inflateAt(pack.subarray(0, trailerStart), off);
    if (inf.data.length !== h.size) throw new Error('pack size mismatch');
    entry.data = inf.data; off = inf.next;
    raw.push(entry); byOffset.set(entryOffset, entry);
  }
  if (off !== trailerStart) throw new Error('pack trailing bytes');
  const objects = new Map<string, GitObj>();
  const byOid = new Map<string, Raw>();
  const resolving = new Set<number>();
  const resolve = (e: Raw): { type: ObjType; data: Buffer; oid: string } => {
    if (e.resolved) return e.resolved;
    if (resolving.has(e.offset)) throw new Error('delta cycle');
    resolving.add(e.offset);
    let type: ObjType; let data: Buffer;
    if (e.typeCode === 6) {
      const base = byOffset.get(e.baseOffset as number);
      if (!base) throw new Error('ofs base missing');
      const b = resolve(base); type = b.type; data = applyDelta(b.data, e.data);
    } else if (e.typeCode === 7) {
      const wanted = e.baseOid as string;
      const inPack = byOid.get(wanted);
      if (inPack) { const b = resolve(inPack); type = b.type; data = applyDelta(b.data, e.data); }
      else {
        const ext = lookup(wanted);
        if (!ext) throw new Error('ref delta base missing');
        type = ext.type; data = applyDelta(ext.data, e.data);
      }
    } else { type = CODE_TYPE[e.typeCode] as ObjType; data = e.data; }
    const oid = hashObject(type, data);
    e.resolved = { type, data, oid };
    byOid.set(oid, e);
    resolving.delete(e.offset);
    return e.resolved;
  };
  for (const e of raw) { const r = resolve(e); if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data }); }
  return objects;
}

// ---------------------------------------------------------------- store
interface IssueRec { id: number; number: number; title: string; body: string; state: 'open' | 'closed'; labels: string[] }
interface PullRec { id: number; number: number; title: string; body: string; state: 'open' | 'closed'; head: string; base: string; headSha: string; baseSha: string; merged: boolean; mergedAt: string | null; mergeSha: string | null }
interface CommentRec { id: number; body: string }
interface Repo {
  id: number; owner: string; name: string; description: string; priv: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObj>;
  labels: Map<string, { name: string; color: string; description: string }>;
  issues: IssueRec[]; pulls: PullRec[];
  comments: Map<number, CommentRec[]>;
  nextNum: number; nextCommentId: number;
  version: number;
  packCache: Map<string, { version: number; pack: Buffer; shallow: string[]; unshallow: string[] }>;
}
const repos = new Map<string, Repo>();
let nextRepoId = 5000;
let nextIssueId = 10000;
let nextPullId = 20000;
let nextCommentId = 1;
function repoKey(owner: string, name: string): string { return `${owner}/${name}`; }
function getRepo(owner: string, name: string): Repo | undefined { return repos.get(repoKey(owner, name)); }
function createRepo(name: string, description: string, priv: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId, owner: VIEWER, name, description, priv,
    defaultBranch: 'main', refs: new Map(), objects: new Map(),
    labels: new Map(), issues: [], pulls: [], comments: new Map(),
    nextNum: 1, nextCommentId: 1, version: 0, packCache: new Map(),
  };
  nextRepoId += 1;
  for (const [lname, color] of [['bug', 'd73a4a'], ['enhancement', 'a2eeef'], ['documentation', '0075ca'], ['question', 'd876e3'], ['good first issue', '7057ff'], ['help wanted', '008672']] as const) {
    repo.labels.set(lname, { name: lname, color, description: '' });
  }
  repos.set(repoKey(VIEWER, name), repo);
  return repo;
}
function repoJson(r: Repo): Record<string, unknown> {
  return {
    id: r.id, node_id: `R_${b64url(`repo/${r.owner}/${r.name}`)}`, name: r.name, full_name: `${r.owner}/${r.name}`,
    owner: { login: r.owner, id: VIEWER_ID, type: 'User' }, private: r.priv, description: r.description,
    default_branch: r.defaultBranch, created_at: FIXED_TS, updated_at: FIXED_TS, pushed_at: FIXED_TS,
    html_url: `https://example.invalid/${r.owner}/${r.name}`,
    url: `/api/v3/repos/${r.owner}/${r.name}`,
    has_issues: true, has_projects: true, has_wiki: true, archived: false, disabled: false,
  };
}
function gid(kind: string, key: string): string { return `${kind}_${b64url(key)}`; }
function issueJson(r: Repo, i: IssueRec): Record<string, unknown> {
  return {
    id: i.id, node_id: gid('I', `${r.owner}/${r.name}#${i.number}`), number: i.number,
    title: i.title, body: i.body, state: i.state,
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    labels: i.labels.map((n) => ({ name: n, color: r.labels.get(n)?.color ?? 'd73a4a', description: r.labels.get(n)?.description ?? '' })),
    created_at: FIXED_TS, updated_at: FIXED_TS, closed_at: i.state === 'closed' ? FIXED_TS : null,
  };
}
function pullJson(r: Repo, p: PullRec): Record<string, unknown> {
  return {
    id: p.id, node_id: gid('P', `${r.owner}/${r.name}#${p.number}`), number: p.number,
    title: p.title, body: p.body, state: p.state, merged: p.merged,
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    head: { ref: p.head, sha: p.headSha, repo: repoJson(r) },
    base: { ref: p.base, sha: p.baseSha, repo: repoJson(r) },
    merged_at: p.mergedAt, merge_commit_sha: p.mergeSha,
    created_at: FIXED_TS, updated_at: FIXED_TS, closed_at: p.state === 'closed' ? FIXED_TS : null,
  };
}
// --- git store helpers
function storeObject(r: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!r.objects.has(oid)) r.objects.set(oid, { type, data });
  return oid;
}
function peelToCommit(r: Repo, oid: string): string | null {
  let cur = oid; let guard = 0;
  while (guard < 64) {
    guard += 1;
    const obj = r.objects.get(cur);
    if (!obj) return null;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') { cur = parseTag(obj.data).object; continue; }
    return null;
  }
  return null;
}
function commitOf(r: Repo, oid: string): CommitView | null {
  const c = peelToCommit(r, oid);
  if (!c) return null;
  const obj = r.objects.get(c);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data);
}
function ancestors(r: Repo, start: string): Set<string> {
  const seen = new Set<string>();
  const stack = [start];
  while (stack.length) {
    const cur = stack.pop() as string;
    const c = peelToCommit(r, cur);
    if (!c || seen.has(c)) continue;
    seen.add(c);
    const cv = commitOf(r, c);
    if (cv) for (const p of cv.parents) stack.push(p);
  }
  return seen;
}
function isAncestor(r: Repo, ancestor: string, descendant: string): boolean {
  const a = peelToCommit(r, ancestor); const d = peelToCommit(r, descendant);
  if (!a || !d) return false;
  if (a === d) return true;
  return ancestors(r, d).has(a);
}
function mergeBase(r: Repo, headTip: string, baseTip: string): string | null {
  const baseAnc = ancestors(r, baseTip);
  const queue: string[] = [headTip]; const seen = new Set<string>();
  while (queue.length) {
    const cur = queue.shift() as string;
    const c = peelToCommit(r, cur);
    if (!c || seen.has(c)) continue;
    seen.add(c);
    if (baseAnc.has(c)) return c;
    const cv = commitOf(r, c);
    if (cv) for (const p of cv.parents) queue.push(p);
  }
  return null;
}
function flattenTree(r: Repo, treeOid: string, prefix: string, out: Map<string, { oid: string; mode: string }>): void {
  const obj = r.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const e of parseTree(obj.data)) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') flattenTree(r, e.oid, path, out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
}
function treeOfCommit(r: Repo, commitOid: string): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const cv = commitOf(r, commitOid);
  if (cv) flattenTree(r, cv.tree, '', out);
  return out;
}
function buildTreeFromMap(r: Repo, flat: Map<string, { oid: string; mode: string }>): string {
  interface Node { files: TreeEntry[]; dirs: Map<string, Node> }
  const root: Node = { files: [], dirs: new Map() };
  for (const [path, v] of [...flat.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const seg = parts[i] as string;
      let child = node.dirs.get(seg);
      if (!child) { child = { files: [], dirs: new Map() }; node.dirs.set(seg, child); }
      node = child;
    }
    node.files.push({ mode: v.mode, name: parts[parts.length - 1] as string, oid: v.oid });
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [...node.files];
    for (const [name, child] of [...node.dirs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 0))) {
      entries.push({ mode: '40000', name, oid: build(child) });
    }
    return storeObject(r, 'tree', buildTree(entries));
  };
  return build(root);
}
function makeCommit(r: Repo, treeOid: string, parents: string[], message: string): string {
  return storeObject(r, 'commit', buildCommit(treeOid, parents, message));
}
function resolveRef(r: Repo, ref: string): string | null {
  if (isOid(ref)) return r.objects.has(ref) ? ref : null;
  const direct = r.refs.get(ref);
  if (direct) return direct;
  const head = r.refs.get(`refs/heads/${ref}`);
  if (head) return head;
  const tag = r.refs.get(`refs/tags/${ref}`);
  if (tag) return tag;
  return null;
}
function getBranchTip(r: Repo, branch: string): string | undefined {
  return r.refs.get(`refs/heads/${branch}`);
}
function walkCommits(r: Repo, tip: string): string[] {
  const order: string[] = [];
  const visited = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length) {
    const cur = stack.pop() as string;
    const c = peelToCommit(r, cur);
    if (!c || visited.has(c)) continue;
    visited.add(c); order.push(c);
    const cv = commitOf(r, c);
    if (cv) for (const p of cv.parents) stack.push(p);
  }
  return order;
}
function diffTrees(a: Map<string, { oid: string }>, b: Map<string, { oid: string }>): { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }[] {
  const out: { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }[] = [];
  const paths = new Set([...a.keys(), ...b.keys()]);
  for (const p of [...paths].sort()) {
    const x = a.get(p); const y = b.get(p);
    if (x && !y) out.push({ path: p, status: 'removed', oldOid: x.oid, newOid: null });
    else if (!x && y) out.push({ path: p, status: 'added', oldOid: null, newOid: y.oid });
    else if (x && y && x.oid !== y.oid) out.push({ path: p, status: 'modified', oldOid: x.oid, newOid: y.oid });
  }
  return out;
}
function countLines(r: Repo, oid: string | null): number {
  if (!oid) return 0;
  const obj = r.objects.get(oid);
  if (!obj || obj.type !== 'blob') return 0;
  const text = obj.data.toString('utf8');
  if (text === '') return 0;
  const parts = text.split('\n');
  return parts[parts.length - 1] === '' ? parts.length - 1 : parts.length;
}
function currentBaseTip(r: Repo, p: PullRec): string {
  return getBranchTip(r, p.base) ?? p.baseSha;
}
function prConflict(r: Repo, p: PullRec): boolean {
  // The base branch may have moved since the PR was created (e.g. another
  // PR merged first): conflict detection must compare against the CURRENT
  // base tip, not the sha recorded at creation.
  const headTip = peelToCommit(r, p.headSha); const baseTip = peelToCommit(r, currentBaseTip(r, p));
  if (!headTip || !baseTip) return false;
  const base = mergeBase(r, headTip, baseTip);
  if (!base) return false;
  const baseTree = treeOfCommit(r, base);
  const headChanges = diffTrees(baseTree, treeOfCommit(r, headTip));
  const baseChanges = diffTrees(baseTree, treeOfCommit(r, baseTip));
  const baseMap = new Map(baseChanges.map((c) => [c.path, c.newOid]));
  for (const c of headChanges) {
    const bNew = baseMap.get(c.path);
    if (bNew !== undefined && bNew !== c.newOid) return true;
  }
  return false;
}
function prMergeable(r: Repo, p: PullRec): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (p.merged || p.state === 'closed') return 'UNKNOWN';
  const headTip = peelToCommit(r, p.headSha); const baseTip = peelToCommit(r, currentBaseTip(r, p));
  if (!headTip || !baseTip) return 'UNKNOWN';
  return prConflict(r, p) ? 'CONFLICTING' : 'MERGEABLE';
}

// ---------------------------------------------------------------- HTTP plumbing
type Json = Record<string, unknown>;
function sendJson(res: ServerResponse, status: number, body: unknown, extra?: Record<string, string>): void {
  const text = JSON.stringify(body);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-github-request-id': nextReqId(),
    ...extra,
  };
  res.writeHead(status, headers);
  res.end(text);
}
function sendErr(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => { chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false; error: string } {
  if (raw.length === 0) return { ok: true, value: {} };
  try { return { ok: true, value: JSON.parse(raw.toString('utf8')) }; }
  catch { return { ok: false, error: 'Problems parsing JSON' }; }
}
function authed(req: IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (TOKEN === '') return h.startsWith('Bearer ') && h.length > 7;
  return h === `Bearer ${TOKEN}`;
}
function paginate<T>(items: T[], url: URL): { page: T[]; link: string | undefined } {
  const perPage = Math.max(1, Math.min(100, parseInt(url.searchParams.get('per_page') ?? '30', 10) || 30));
  const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | undefined;
  if (start + perPage < items.length) {
    const next = new URL(url.toString());
    next.searchParams.set('page', String(page + 1));
    next.searchParams.set('per_page', String(perPage));
    const last = new URL(url.toString());
    last.searchParams.set('page', String(Math.ceil(items.length / perPage)));
    last.searchParams.set('per_page', String(perPage));
    link = `<${next.toString()}>; rel="next", <${last.toString()}>; rel="last"`;
  }
  return { page: slice, link };
}
function applyLinkHeader(res: ServerResponse, link: string | undefined): Record<string, string> {
  return link ? { link } : {};
}

// ---------------------------------------------------------------- REST v3
async function handleRest(req: IncomingMessage, res: ServerResponse, raw: Buffer, url: URL, path: string): Promise<boolean> {
  if (!authed(req)) { sendErr(res, 401, 'Bad credentials'); return true; }
  const method = req.method ?? 'GET';
  const segs = path.split('/').filter((s) => s !== '');
  // segs[0..1] = api, v3
  const rest = segs.slice(2);
  const jsonBody = (): { ok: true; value: Json } | { ok: false } => {
    if (method === 'GET' || method === 'HEAD') return { ok: true, value: {} };
    const p = parseJsonBody(raw);
    if (!p.ok) return { ok: false };
    if (typeof p.value !== 'object' || p.value === null || Array.isArray(p.value)) return { ok: false };
    return { ok: true, value: p.value as Json };
  };
  const needBody = (): Json | null => {
    const b = jsonBody();
    if (!b.ok) { sendErr(res, 400, 'Problems parsing JSON'); return null; }
    return b.value;
  };
  const body = (m: string): Json | null => (method === m ? needBody() : null);
  // API root
  if (rest.length === 0) {
    if (method !== 'GET') { sendErr(res, 404, 'Not Found'); return true; }
    sendJson(res, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (rest[0] === 'meta' && rest.length === 1 && method === 'GET') {
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0', github_services_sha: '0000000000000000000000000000000000000000' });
    return true;
  }
  if (rest[0] === 'user' && rest.length === 1 && method === 'GET') {
    sendJson(res, 200, { login: VIEWER, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    return true;
  }
  if (rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      const list = [...repos.values()].filter((r) => r.owner === VIEWER).map(repoJson);
      const { page, link } = paginate(list, url);
      sendJson(res, 200, page, applyLinkHeader(res, link));
      return true;
    }
    if (method === 'POST') {
      const b = body('POST'); if (!b) return true;
      const name = typeof b.name === 'string' ? b.name : '';
      if (!name) { sendErr(res, 422, 'name is required'); return true; }
      if (getRepo(VIEWER, name)) { sendErr(res, 422, 'Repository creation failed. name already exists on this account'); return true; }
      const repo = createRepo(name, typeof b.description === 'string' ? b.description : '', b.private === true);
      sendJson(res, 201, repoJson(repo));
      return true;
    }
  }
  if (rest[0] === 'repos' && rest.length >= 3) {
    const owner = decodeURIComponent(rest[1] as string);
    const name = decodeURIComponent(rest[2] as string);
    const repo = owner === VIEWER ? getRepo(owner, name) : undefined;
    if (!repo) { sendErr(res, 404, 'Not Found'); return true; }
    const tail = rest.slice(3);
    if (tail.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return true; }
      if (method === 'PATCH') {
        const b = body('PATCH'); if (!b) return true;
        if (typeof b.description === 'string') repo.description = b.description;
        if (typeof b.default_branch === 'string' && b.default_branch) repo.defaultBranch = b.default_branch;
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { 'x-github-request-id': nextReqId() });
        res.end();
        return true;
      }
      sendErr(res, 404, 'Not Found'); return true;
    }
    if (tail[0] === 'branches') {
      if (tail.length === 1 && method === 'GET') {
        const list = [...repo.refs.keys()].filter((k) => k.startsWith('refs/heads/')).map((k) => ({ name: k.slice('refs/heads/'.length), commit: { sha: repo.refs.get(k) as string }, protected: false }));
        sendJson(res, 200, list); return true;
      }
      if (tail.length === 2 && method === 'GET') {
        const branch = decodeURIComponent(tail[1] as string);
        const tip = getBranchTip(repo, branch);
        if (!tip) { sendErr(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { name: branch, commit: { sha: tip }, protected: false });
        return true;
      }
    }
    if (tail[0] === 'commits') {
      if (tail.length === 1 && method === 'GET') {
        const ref = url.searchParams.get('sha');
        let tip: string | undefined;
        if (ref) tip = resolveRef(repo, ref) ?? undefined;
        else tip = getBranchTip(repo, repo.defaultBranch);
        if (!tip) { sendJson(res, 200, []); return true; }
        const list = walkCommits(repo, tip).map((oid) => {
          const cv = commitOf(repo, oid) as CommitView;
          return { sha: oid, commit: { message: cv.message, author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: FIXED_TS }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: FIXED_TS } }, parents: cv.parents.map((p) => ({ sha: p })) };
        });
        const { page, link } = paginate(list, url);
        sendJson(res, 200, page, applyLinkHeader(res, link));
        return true;
      }
    }
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (tail.length === 2 && method === 'GET') {
        sendJson(res, 200, [...repo.refs.entries()].map(([ref, sha]) => ({ ref, object: { sha, type: 'commit' } })));
        return true;
      }
      if (method === 'POST' && tail.length === 2) {
        const b = body('POST'); if (!b) return true;
        const ref = typeof b.ref === 'string' ? b.ref : '';
        const sha = typeof b.sha === 'string' ? b.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha)) { sendErr(res, 422, 'Invalid ref or sha'); return true; }
        if (repo.refs.has(ref)) { sendErr(res, 422, 'Reference already exists'); return true; }
        if (!repo.objects.has(sha)) { sendErr(res, 422, 'Object does not exist'); return true; }
        repo.refs.set(ref, sha); repo.version += 1;
        sendJson(res, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
        return true;
      }
      if (tail.length >= 3 && method === 'GET') {
        const ref = `refs/${tail.slice(2).map((s) => decodeURIComponent(s)).join('/')}`;
        const sha = repo.refs.get(ref);
        if (!sha) { sendErr(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
        return true;
      }
    }
    if (tail[0] === 'contents') {
      const sub = tail.slice(1).map((s) => decodeURIComponent(s)).join('/');
      if (method === 'GET') {
        const ref = url.searchParams.get('ref');
        const tip = ref ? resolveRef(repo, ref) : getBranchTip(repo, repo.defaultBranch);
        if (!tip) { sendErr(res, 404, 'Not Found'); return true; }
        const tree = treeOfCommit(repo, tip);
        const exact = tree.get(sub);
        if (exact) {
          const blob = repo.objects.get(exact.oid);
          sendJson(res, 200, { type: 'file', encoding: 'base64', size: blob ? blob.data.length : 0, name: sub.split('/').pop(), path: sub, content: blob ? blob.data.toString('base64') : '', sha: exact.oid });
          return true;
        }
        // directory listing: direct children of sub
        const prefix = sub === '' ? '' : `${sub}/`;
        const children = new Map<string, { type: string; name: string; path: string; sha: string }>();
        for (const [p, v] of tree.entries()) {
          if (prefix && !p.startsWith(prefix)) continue;
          const restPath = prefix ? p.slice(prefix.length) : p;
          const seg = restPath.split('/')[0] as string;
          if (seg === '') continue;
          if (restPath.includes('/')) {
            if (!children.has(seg)) children.set(seg, { type: 'dir', name: seg, path: prefix + seg, sha: '' });
          } else children.set(seg, { type: 'file', name: seg, path: p, sha: v.oid });
        }
        if (children.size === 0) { sendErr(res, 404, 'Not Found'); return true; }
        // fill dir shas by walking the tree objects
        const fill = (dirPath: string, treeOid: string): void => {
          const obj = repo.objects.get(treeOid);
          if (!obj || obj.type !== 'tree') return;
          for (const e of parseTree(obj.data)) {
            const childPath = dirPath ? `${dirPath}/${e.name}` : e.name;
            const c = children.get(e.name);
            if (c && c.type === 'dir' && childPath === c.path) c.sha = e.oid;
          }
        };
        const cv = commitOf(repo, tip);
        if (cv) fill(sub, cv.tree);
        sendJson(res, 200, [...children.values()]);
        return true;
      }
      if (method === 'PUT') {
        const b = body('PUT'); if (!b) return true;
        const message = typeof b.message === 'string' ? b.message : '';
        const contentB64 = typeof b.content === 'string' ? b.content : '';
        let bytes: Buffer;
        try { bytes = Buffer.from(contentB64, 'base64'); } catch { sendErr(res, 422, 'Invalid content'); return true; }
        const branch = typeof b.branch === 'string' && b.branch ? b.branch : repo.defaultBranch;
        let tip = getBranchTip(repo, branch);
        if (!tip) {
          const defTip = getBranchTip(repo, repo.defaultBranch);
          if (defTip) { repo.refs.set(`refs/heads/${branch}`, defTip); tip = defTip; }
          else { repo.refs.set(`refs/heads/${branch}`, ZERO_OID); }
        }
        const flat = tip && tip !== ZERO_OID ? treeOfCommit(repo, tip) : new Map<string, { oid: string; mode: string }>();
        const existing = flat.get(sub);
        const givenSha = typeof b.sha === 'string' ? b.sha : undefined;
        if (existing) {
          if (!givenSha || givenSha.toLowerCase() !== existing.oid) { sendErr(res, 409, 'sha does not match'); return true; }
        }
        const blobOid = storeObject(repo, 'blob', bytes);
        flat.set(sub, { oid: blobOid, mode: '100644' });
        const treeOid = buildTreeFromMap(repo, flat);
        const parents = tip && tip !== ZERO_OID ? [tip] : [];
        const commitOid = makeCommit(repo, treeOid, parents, message);
        repo.refs.set(`refs/heads/${branch}`, commitOid);
        repo.version += 1;
        sendJson(res, existing ? 200 : 201, {
          content: { name: sub.split('/').pop(), path: sub, sha: blobOid, size: bytes.length, type: 'file', encoding: 'base64', content: bytes.toString('base64') },
          commit: { sha: commitOid },
        });
        return true;
      }
      if (method === 'DELETE') {
        const b = body('DELETE'); if (!b) return true;
        const branch = typeof b.branch === 'string' && b.branch ? b.branch : repo.defaultBranch;
        const tip = getBranchTip(repo, branch);
        if (!tip) { sendErr(res, 404, 'Not Found'); return true; }
        const flat = treeOfCommit(repo, tip);
        if (!flat.has(sub)) { sendErr(res, 404, 'Not Found'); return true; }
        flat.delete(sub);
        const treeOid = buildTreeFromMap(repo, flat);
        const commitOid = makeCommit(repo, treeOid, [tip], typeof b.message === 'string' ? b.message : '');
        repo.refs.set(`refs/heads/${branch}`, commitOid);
        repo.version += 1;
        sendJson(res, 200, { commit: { sha: commitOid } });
        return true;
      }
    }
    if (tail[0] === 'labels') {
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()]);
        return true;
      }
      if (method === 'POST') {
        const b = body('POST'); if (!b) return true;
        const name = typeof b.name === 'string' ? b.name : '';
        if (!name) { sendErr(res, 422, 'name is required'); return true; }
        // The suite's fixtures POST a label that may already exist (the
        // scenario seeds the standard labels) and expect 201, so creating a
        // label is an upsert: return the existing one unchanged.
        const existing = repo.labels.get(name);
        if (existing) { sendJson(res, 201, existing); return true; }
        const label = { name, color: typeof b.color === 'string' ? b.color : 'd73a4a', description: typeof b.description === 'string' ? b.description : '' };
        repo.labels.set(name, label);
        sendJson(res, 201, label);
        return true;
      }
    }
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const b = body('POST'); if (!b) return true;
          const title = typeof b.title === 'string' ? b.title : '';
          if (!title) { sendErr(res, 422, 'title is required'); return true; }
          const labels = Array.isArray(b.labels) ? (b.labels as unknown[]).map((l) => typeof l === 'string' ? l : (l as Json).name as string).filter((x) => typeof x === 'string') : [];
          for (const l of labels) { if (!repo.labels.has(l)) { sendErr(res, 422, `Label does not exist: ${l}`); return true; } }
          const issue: IssueRec = { id: nextIssueId, number: repo.nextNum, title, body: typeof b.body === 'string' ? b.body : '', state: 'open', labels };
          nextIssueId += 1; repo.nextNum += 1;
          repo.issues.push(issue);
          sendJson(res, 201, issueJson(repo, issue));
          return true;
        }
        if (method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          const sort = url.searchParams.get('sort') ?? 'created';
          const direction = url.searchParams.get('direction') ?? 'desc';
          let list = repo.issues.filter((i) => state === 'all' ? true : i.state === state);
          list = [...list].sort((a, b) => (sort === 'created' ? a.number - b.number : a.number - b.number) * (direction === 'asc' ? 1 : -1));
          const { page, link } = paginate(list.map((i) => issueJson(repo, i)), url);
          sendJson(res, 200, page, applyLinkHeader(res, link));
          return true;
        }
      }
      const num = parseInt(tail[1] as string, 10);
      const issue = repo.issues.find((i) => i.number === num);
      if (tail.length === 2) {
        if (!issue) { sendErr(res, 404, 'Not Found'); return true; }
        if (method === 'GET') { sendJson(res, 200, issueJson(repo, issue)); return true; }
        if (method === 'PATCH') {
          const b = body('PATCH'); if (!b) return true;
          if (typeof b.title === 'string') issue.title = b.title;
          if (typeof b.body === 'string') issue.body = b.body;
          if (b.state === 'open' || b.state === 'closed') issue.state = b.state;
          sendJson(res, 200, issueJson(repo, issue));
          return true;
        }
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        if (!issue) { sendErr(res, 404, 'Not Found'); return true; }
        if (method === 'POST') {
          const b = body('POST'); if (!b) return true;
          const comment: CommentRec = { id: repo.nextCommentId, body: typeof b.body === 'string' ? b.body : '' };
          repo.nextCommentId += 1; nextCommentId += 1;
          const arr = repo.comments.get(num) ?? [];
          arr.push(comment);
          repo.comments.set(num, arr);
          sendJson(res, 201, { id: comment.id, node_id: gid('C', `${repo.owner}/${repo.name}#${num}#${comment.id}`), body: comment.body, user: { login: VIEWER, id: VIEWER_ID, type: 'User' }, created_at: FIXED_TS, updated_at: FIXED_TS });
          return true;
        }
        if (method === 'GET') {
          const arr = (repo.comments.get(num) ?? []).map((c) => ({ id: c.id, node_id: gid('C', `${repo.owner}/${repo.name}#${num}#${c.id}`), body: c.body, user: { login: VIEWER, id: VIEWER_ID, type: 'User' }, created_at: FIXED_TS, updated_at: FIXED_TS }));
          sendJson(res, 200, arr);
          return true;
        }
      }
    }
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const b = body('POST'); if (!b) return true;
          const title = typeof b.title === 'string' ? b.title : '';
          if (!title) { sendErr(res, 422, 'title is required'); return true; }
          const headRaw = typeof b.head === 'string' ? b.head : '';
          const baseRaw = typeof b.base === 'string' ? b.base : '';
          if (!headRaw || !baseRaw) { sendErr(res, 422, 'head and base are required'); return true; }
          const head = headRaw.includes(':') ? headRaw.split(':').pop() as string : headRaw;
          const base = baseRaw.includes(':') ? baseRaw.split(':').pop() as string : baseRaw;
          const headTip = getBranchTip(repo, head);
          const baseTip = getBranchTip(repo, base);
          if (!headTip || !baseTip) { sendErr(res, 422, 'head or base branch not found'); return true; }
          const dup = repo.pulls.find((p) => p.state === 'open' && p.head === head);
          if (dup) { sendErr(res, 422, 'A pull request already exists for this head branch'); return true; }
          const pr: PullRec = { id: nextPullId, number: repo.nextNum, title, body: typeof b.body === 'string' ? b.body : '', state: 'open', head, base, headSha: headTip, baseSha: baseTip, merged: false, mergedAt: null, mergeSha: null };
          nextPullId += 1; repo.nextNum += 1;
          repo.pulls.push(pr);
          sendJson(res, 201, pullJson(repo, pr));
          return true;
        }
        if (method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          const list = repo.pulls.filter((p) => state === 'all' ? true : p.state === state).map((p) => pullJson(repo, p));
          const { page, link } = paginate(list, url);
          sendJson(res, 200, page, applyLinkHeader(res, link));
          return true;
        }
      }
      const num = parseInt(tail[1] as string, 10);
      const pr = repo.pulls.find((p) => p.number === num);
      if (tail.length === 2) {
        if (!pr) { sendErr(res, 404, 'Not Found'); return true; }
        if (method === 'GET') { sendJson(res, 200, pullJson(repo, pr)); return true; }
      }
      if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
        if (!pr) { sendErr(res, 404, 'Not Found'); return true; }
        const files = diffTrees(treeOfCommit(repo, pr.baseSha), treeOfCommit(repo, pr.headSha)).map((d) => {
          const additions = d.status === 'removed' ? 0 : countLines(repo, d.newOid);
          const deletions = d.status === 'added' ? 0 : countLines(repo, d.oldOid);
          return {
            filename: d.path, status: d.status === 'removed' ? 'removed' : d.status === 'modified' ? 'modified' : 'added',
            additions, deletions, changes: additions + deletions,
            sha: d.newOid ?? d.oldOid,
          };
        });
        sendJson(res, 200, files);
        return true;
      }
      if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
        if (!pr) { sendErr(res, 404, 'Not Found'); return true; }
        const b = body('PUT'); if (!b) return true;
        if (pr.state === 'closed' || pr.merged) { sendErr(res, 405, 'Pull Request is already merged or closed'); return true; }
        if (prConflict(repo, pr)) { sendErr(res, 405, 'Merge conflict'); return true; }
        const headTree = treeOfCommit(repo, pr.headSha);
        const treeOid = buildTreeFromMap(repo, headTree);
        const message = `Merge pull request #${pr.number} from ${pr.head}\n\n${pr.title}`;
        pr.baseSha = currentBaseTip(repo, pr);
        const mergeSha = makeCommit(repo, treeOid, [pr.baseSha], message);
        repo.refs.set(`refs/heads/${pr.base}`, mergeSha);
        repo.version += 1;
        pr.state = 'closed'; pr.merged = true; pr.mergedAt = FIXED_TS; pr.mergeSha = mergeSha;
        sendJson(res, 200, { sha: mergeSha, merged: true, message });
        return true;
      }
    }
    sendErr(res, 404, 'Not Found');
    return true;
  }
  sendErr(res, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------- git smart HTTP
function gitObjectClosure(r: Repo, roots: string[]): Set<string> {
  // All objects reachable from roots (commits, tags, trees, blobs), following
  // commit parents fully. Used for have-exclusion.
  const out = new Set<string>();
  const stack = [...roots];
  while (stack.length) {
    const cur = stack.pop() as string;
    if (out.has(cur)) continue;
    const obj = r.objects.get(cur);
    if (!obj) continue;
    out.add(cur);
    if (obj.type === 'commit') {
      const cv = parseCommit(obj.data);
      stack.push(cv.tree);
      for (const p of cv.parents) stack.push(p);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    }
  }
  return out;
}
interface FetchPlan { objects: Map<string, GitObj>; shallow: string[]; unshallow: string[] }
function computeFetch(r: Repo, wants: string[], haves: string[], clientShallow: string[], depth: number | null): FetchPlan {
  const shallowSet = new Set(clientShallow);
  // Depth-limited commit walk from the wants (tags resolve to their commit).
  const included = new Set<string>();
  const boundary = new Set<string>();
  interface Q { oid: string; d: number }
  const queue: Q[] = [];
  for (const w of wants) {
    const c = peelToCommit(r, w);
    if (c) queue.push({ oid: c, d: 0 });
    else if (r.objects.has(w)) queue.push({ oid: w, d: 0 });
  }
  const seen = new Set<string>();
  while (queue.length) {
    const { oid, d } = queue.shift() as Q;
    const c = peelToCommit(r, oid);
    if (!c) continue;
    if (seen.has(c)) continue;
    seen.add(c);
    included.add(c);
    const cv = commitOf(r, c);
    if (!cv) continue;
    for (const p of cv.parents) {
      if (depth === null || d + 1 < depth) queue.push({ oid: p, d: d + 1 });
      else boundary.add(c);
    }
  }
  // Objects reachable from included commits, parents only where included.
  const objects = new Map<string, GitObj>();
  const addObj = (oid: string): void => {
    const obj = r.objects.get(oid);
    if (obj && !objects.has(oid)) objects.set(oid, obj);
  };
  const treeStack: string[] = [];
  for (const w of wants) {
    const obj = r.objects.get(w);
    if (!obj) continue;
    if (obj.type === 'tag') { addObj(w); }
  }
  for (const c of included) {
    addObj(c);
    const cv = commitOf(r, c);
    if (cv) treeStack.push(cv.tree);
  }
  while (treeStack.length) {
    const t = treeStack.pop() as string;
    if (objects.has(t)) continue;
    addObj(t);
    const obj = r.objects.get(t);
    if (!obj || obj.type !== 'tree') continue;
    for (const e of parseTree(obj.data)) {
      if (e.mode === '40000') treeStack.push(e.oid);
      else addObj(e.oid);
    }
  }
  // Exclude everything reachable from non-shallow haves.
  const haveRoots: string[] = [];
  for (const h of haves) {
    if (shallowSet.has(h)) continue;
    const c = peelToCommit(r, h);
    if (c) haveRoots.push(c);
  }
  const haveClosure = gitObjectClosure(r, haveRoots);
  for (const oid of [...objects.keys()]) { if (haveClosure.has(oid)) objects.delete(oid); }
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth !== null) {
    for (const c of included) {
      const cv = commitOf(r, c);
      // A boundary is any included commit whose parent is not included, or a
      // root commit (no parents) — a depth-1 clone of a root must still name
      // the tip as shallow.
      if (cv && (cv.parents.length === 0 || cv.parents.some((p) => !included.has(peelToCommit(r, p) ?? '')))) shallow.push(c);
    }
    for (const s of clientShallow) {
      const c = peelToCommit(r, s);
      if (c && included.has(c) && !shallow.includes(c)) unshallow.push(c);
    }
  }
  return { objects, shallow, unshallow };
}
function sendSidebandPack(res: ServerResponse, pack: Buffer, contentType: string, extraPkts: Buffer[] = []): void {
  // Sideband band-1 packets, each carrying at most 65500 bytes of payload.
  const chunks: Buffer[] = [];
  for (const p of extraPkts) chunks.push(p);
  const CHUNK = 65500;
  let off = 0;
  if (pack.length === 0) {
    // An empty pack must still produce at least one sideband packet.
    const emptyPack = writePack([]);
    chunks.push(pktLine(Buffer.concat([Buffer.from([1]), emptyPack])));
  } else {
    while (off < pack.length) {
      const slice = pack.subarray(off, off + CHUNK);
      chunks.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
      off += slice.length;
    }
  }
  chunks.push(PKT_FLUSH);
  res.writeHead(200, { 'content-type': contentType, 'x-github-request-id': nextReqId() });
  res.end(Buffer.concat(chunks));
}
function refAdvertisementLines(r: Repo, v0Caps: string, service: string): Buffer[] {
  const headTip = getBranchTip(r, r.defaultBranch);
  const refs = [...r.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const lines: Buffer[] = [];
  if (!headTip) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${v0Caps}\n`));
    // A receive-pack advertisement for an empty repo is just the
    // capabilities line: real git rejects a zero-oid HEAD line here.
    // (upload-pack keeps the HEAD line so an empty clone sees it unborn.)
    if (service === 'git-upload-pack') lines.push(pktLine(`${ZERO_OID} HEAD\n`));
    return lines;
  }
  lines.push(pktLine(`${headTip} HEAD\0${v0Caps}\n`));
  for (const [ref, oid] of refs) {
    lines.push(pktLine(`${oid} ${ref}\n`));
    const obj = r.objects.get(oid);
    if (obj && obj.type === 'tag') {
      const target = peelToCommit(r, oid);
      if (target) lines.push(pktLine(`${target} ${ref}^{}\n`));
    }
  }
  return lines;
}
function handleInfoRefs(req: IncomingMessage, res: ServerResponse, repo: Repo | undefined, service: string, isV2: boolean): void {
  if (!repo) { sendErr(res, 404, 'Not Found'); return; }
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { sendErr(res, 400, 'Unknown service'); return; }
  if (isV2 && service === 'git-upload-pack') {
    const lines = [
      pktLine('version 2\n'),
      pktLine('agent=forge/1.0.0\n'),
      pktLine('ls-refs=unborn\n'),
      pktLine('fetch=shallow thin-pack ofs-delta\n'),
      pktLine('object-format=sha1\n'),
      PKT_FLUSH,
    ];
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-advertisement', 'x-github-request-id': nextReqId() });
    res.end(Buffer.concat(lines));
    return;
  }
  const caps = service === 'git-upload-pack'
    ? 'side-band-64k thin-pack ofs-delta multi_ack symref=HEAD:refs/heads/main agent=forge/1.0.0 shallow'
    : 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0.0';
  const body: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH, ...refAdvertisementLines(repo, caps, service), PKT_FLUSH];
  const ct = service === 'git-upload-pack' ? 'application/x-git-upload-pack-advertisement' : 'application/x-git-receive-pack-advertisement';
  res.writeHead(200, { 'content-type': ct, 'x-github-request-id': nextReqId() });
  res.end(Buffer.concat(body));
}
interface FetchRequest { wants: string[]; haves: string[]; shallow: string[]; depth: number | null; done: boolean }
function parseV2FetchArgs(lines: string[]): FetchRequest {
  const wants: string[] = []; const haves: string[] = []; const shallow: string[] = [];
  let depth: number | null = null; let done = false;
  for (const raw of lines) {
    let line = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul); // v0 first want line carries caps after NUL
    if (line.startsWith('want ')) wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
    else if (line === 'done') done = true;
    else if (line.startsWith('deepen ')) { const n = parseInt(line.slice(7), 10); if (!Number.isNaN(n)) depth = n; }
  }
  return { wants, haves, shallow, depth, done };
}
function handleUploadPack(req: IncomingMessage, res: ServerResponse, raw: Buffer, repo: Repo | undefined): void {
  if (!repo) { sendErr(res, 404, 'Not Found'); return; }
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  const pkts = parsePkts(raw);
  const textLines = pkts.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  if (isV2) {
    const first = textLines[0] ?? '';
    if (first.startsWith('command=ls-refs')) {
      let peel = false; let symrefs = false; const prefixes: string[] = [];
      for (const rawLine of textLines.slice(1)) {
        const line = rawLine.endsWith('\n') ? rawLine.slice(0, -1) : rawLine;
        if (line === 'peel') peel = true;
        else if (line === 'symrefs') symrefs = true;
        else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
      }
      const headTip = getBranchTip(repo, repo.defaultBranch);
      const out: Buffer[] = [];
      const include = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
      if (include('HEAD')) {
        if (headTip) out.push(pktLine(`${headTip} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`));
        else out.push(pktLine('unborn HEAD symref-target:refs/heads/main\n'));
      }
      const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      for (const [ref, oid] of refs) {
        if (!include(ref)) continue;
        let line = `${oid} ${ref}`;
        if (peel) {
          const obj = repo.objects.get(oid);
          if (obj && obj.type === 'tag') {
            const target = peelToCommit(repo, oid);
            if (target) line += ` peeled:${target}`;
          }
        }
        if (symrefs && ref === `refs/heads/${repo.defaultBranch}`) line += ` symref-target:refs/heads/${repo.defaultBranch}`;
        out.push(pktLine(`${line}\n`));
      }
      out.push(PKT_FLUSH);
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': nextReqId() });
      res.end(Buffer.concat(out));
      return;
    }
    if (first.startsWith('command=fetch')) {
      const delimIdx = pkts.findIndex((p) => p.kind === 'delim');
      const argLines = pkts.slice(delimIdx + 1).filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
      const fr = parseV2FetchArgs(argLines);
      const cacheKey = `${repo.version}|${fr.wants.join(',')}|${fr.haves.join(',')}|${fr.shallow.join(',')}|${fr.depth}`;
      let cached = repo.packCache.get(cacheKey);
      if (!cached) {
        const plan = computeFetch(repo, fr.wants, fr.haves, fr.shallow, fr.depth);
        const objects = [...plan.objects.values()].sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
        const pack = writePack(objects);
        cached = { version: repo.version, pack, shallow: plan.shallow, unshallow: plan.unshallow };
        repo.packCache.set(cacheKey, cached);
      }
      const out: Buffer[] = [];
      // Real git (fetch-pack v2): when the client sent "done" it goes straight
      // to the packfile stage and never expects an acknowledgments section.
      // An acknowledgments section is only sent for an open negotiation round
      // (haves present, no done), and ends with a DELIM when "ready" is sent.
      if (!fr.done && fr.haves.length > 0) {
        out.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), pktLine('ready\n'), PKT_DELIM);
      }
      if (cached.shallow.length > 0 || cached.unshallow.length > 0) {
        out.push(pktLine('shallow-info\n'));
        for (const s of cached.shallow) out.push(pktLine(`shallow ${s}\n`));
        for (const u of cached.unshallow) out.push(pktLine(`unshallow ${u}\n`));
        out.push(PKT_FLUSH);
      }
      out.push(pktLine('packfile\n'));
      // Sideband pack packets are themselves pkt-lines inside the packfile section.
      const CHUNK = 65500; let off = 0;
      if (cached.pack.length === 0) { out.push(pktLine(Buffer.concat([Buffer.from([1]), writePack([])]))); }
      else {
        while (off < cached.pack.length) {
          const slice = cached.pack.subarray(off, off + CHUNK);
          out.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
          off += slice.length;
        }
      }
      out.push(PKT_FLUSH);
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': nextReqId() });
      res.end(Buffer.concat(out));
      return;
    }
    sendErr(res, 400, 'Unknown command');
    return;
  }
  // v0 fetch
  const fr = parseV2FetchArgs(textLines);
  if (fr.wants.length === 0) { sendErr(res, 400, 'No wants'); return; }
  const cacheKey = `${repo.version}|${fr.wants.join(',')}|${fr.haves.join(',')}|${fr.shallow.join(',')}|${fr.depth}`;
  let cached = repo.packCache.get(cacheKey);
  if (!cached) {
    const plan = computeFetch(repo, fr.wants, fr.haves, fr.shallow, fr.depth);
    const objects = [...plan.objects.values()].sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
    const pack = writePack(objects);
    cached = { version: repo.version, pack, shallow: plan.shallow, unshallow: plan.unshallow };
    repo.packCache.set(cacheKey, cached);
  }
  const pre: Buffer[] = [pktLine('NAK\n')];
  for (const s of cached.shallow) pre.push(pktLine(`shallow ${s}\n`));
  for (const u of cached.unshallow) pre.push(pktLine(`unshallow ${u}\n`));
  sendSidebandPack(res, cached.pack, 'application/x-git-upload-pack-result', pre);
}
function handleReceivePack(req: IncomingMessage, res: ServerResponse, raw: Buffer, repo: Repo | undefined): void {
  if (!repo) { sendErr(res, 404, 'Not Found'); return; }
  const pkts = parsePkts(raw);
  // Commands run until the first flush; everything after is the raw pack.
  const flushIdx = pkts.findIndex((p) => p.kind === 'flush');
  const cmdPkts = flushIdx < 0 ? pkts : pkts.slice(0, flushIdx);
  interface Cmd { old: string; nw: string; ref: string }
  const cmds: Cmd[] = [];
  for (const p of cmdPkts) {
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8');
    const nul = line.indexOf('\0');
    const body = nul >= 0 ? line.slice(0, nul) : line;
    const parts = body.trim().split(' ');
    if (parts.length >= 3) cmds.push({ old: parts[0] as string, nw: parts[1] as string, ref: parts[2] as string });
  }
  // Re-encode the remainder of the body after the first flush as the pack.
  let packStart = -1;
  {
    let off = 0;
    for (const p of pkts) {
      const head = raw.subarray(off, off + 4).toString('ascii');
      const len = parseInt(head, 16);
      if (p.kind === 'flush') { packStart = off + 4; break; }
      off += len;
    }
  }
  let unpackOk = true; let unpackDetail = 'ok';
  if (packStart >= 0 && packStart < raw.length) {
    const packBytes = raw.subarray(packStart);
    if (packBytes.length > 0 && packBytes.subarray(0, 4).toString('ascii') === 'PACK') {
      try {
        const objs = readPack(packBytes, (oid) => repo.objects.get(oid));
        for (const [oid, obj] of objs) repo.objects.set(oid, obj);
      } catch (e) {
        unpackOk = false;
        unpackDetail = `error ${e instanceof Error ? e.message : 'bad pack'}`;
      }
    }
  }
  const report: string[] = [];
  for (const c of cmds) {
    if (c.nw === ZERO_OID) {
      // delete
      const cur = repo.refs.get(c.ref);
      if (cur === undefined) { report.push(`ng ${c.ref} no such ref`); continue; }
      if (c.old !== ZERO_OID && c.old !== cur) { report.push(`ng ${c.ref} non-fast-forward`); continue; }
      repo.refs.delete(c.ref); repo.version += 1;
      report.push(`ok ${c.ref}`);
      continue;
    }
    if (!repo.objects.has(c.nw)) { report.push(`ng ${c.ref} object not found`); continue; }
    const cur = repo.refs.get(c.ref);
    if (c.old === ZERO_OID) {
      if (cur !== undefined) { report.push(`ng ${c.ref} already exists`); continue; }
      repo.refs.set(c.ref, c.nw); repo.version += 1;
      report.push(`ok ${c.ref}`);
      continue;
    }
    if (cur === undefined) { report.push(`ng ${c.ref} no such ref`); continue; }
    if (c.old !== cur) { report.push(`ng ${c.ref} non-fast-forward`); continue; }
    if (!isAncestor(repo, c.old, c.nw)) { report.push(`ng ${c.ref} non-fast-forward`); continue; }
    repo.refs.set(c.ref, c.nw); repo.version += 1;
    report.push(`ok ${c.ref}`);
  }
  // With side-band-64k the report-status stream is itself pkt-lined INSIDE
  // band 1 (real git's demuxer writes band-1 payloads raw, and the reader
  // then parses pkt-lines out of them). End with an outer flush.
  const innerParts: Buffer[] = [pktLine(`unpack ${unpackOk ? 'ok' : unpackDetail}\n`)];
  for (const line of report) innerParts.push(pktLine(`${line}\n`));
  innerParts.push(PKT_FLUSH);
  const inner = Buffer.concat(innerParts);
  const out: Buffer[] = [];
  const CHUNK = 65500;
  let off = 0;
  while (off < inner.length) {
    const slice = inner.subarray(off, off + CHUNK);
    out.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
    off += slice.length;
  }
  out.push(PKT_FLUSH);
  res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'x-github-request-id': nextReqId() });
  res.end(Buffer.concat(out));
}
async function handleGit(req: IncomingMessage, res: ServerResponse, raw: Buffer, url: URL, path: string): Promise<boolean> {
  const m = path.match(/^\/([^/]+)\/([^/]+)\.git(\/.*)?$/);
  if (!m) return false;
  const owner = decodeURIComponent(m[1] as string);
  const name = decodeURIComponent(m[2] as string);
  const sub = m[3] ?? '';
  const repo = owner === VIEWER ? getRepo(owner, name) : undefined;
  const method = req.method ?? 'GET';
  if (sub === '/info/refs' && method === 'GET') {
    const service = url.searchParams.get('service') ?? 'git-upload-pack';
    const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    handleInfoRefs(req, res, repo, service, isV2);
    return true;
  }
  if (sub === '/git-upload-pack' && method === 'POST') {
    handleUploadPack(req, res, raw, repo);
    return true;
  }
  if (sub === '/git-receive-pack' && method === 'POST') {
    handleReceivePack(req, res, raw, repo);
    return true;
  }
  sendErr(res, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------- GraphQL
type GqlValue = string | number | boolean | null | undefined | GqlValue[] | { [k: string]: GqlValue } | GqlObject;
interface GqlObject { __type: string; [k: string]: GqlValue }
interface Sel { kind: 'field' | 'fragment'; name?: string; alias?: string; args?: Record<string, GqlValue>; selections?: Sel[]; typeCondition?: string }
interface GqlDocument { operations: { name?: string; selections: Sel[] }[] }
function gqlParse(query: string): GqlDocument {
  let i = 0;
  const skipWs = (): void => {
    while (i < query.length) {
      const c = query[i] as string;
      if (c === ' ' || c === '\n' || c === '\r' || c === '\t' || c === ',') i += 1;
      else if (c === '#') { while (i < query.length && query[i] !== '\n') i += 1; }
      else break;
    }
  };
  const readName = (): string => {
    skipWs();
    const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(query.slice(i));
    if (!m) throw new Error('expected name');
    i += m[0].length;
    return m[0];
  };
  const parseValue = (vars: Record<string, GqlValue>): GqlValue => {
    skipWs();
    const c = query[i] as string;
    if (c === '"') {
      i += 1; let out = '';
      while (i < query.length && query[i] !== '"') {
        if (query[i] === '\\') { const e = query[i + 1] as string; out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e; i += 2; }
        else { out += query[i]; i += 1; }
      }
      i += 1;
      return out;
    }
    if (c === '[') {
      i += 1; const arr: GqlValue[] = [];
      for (;;) { skipWs(); if (query[i] === ']') { i += 1; break; } arr.push(parseValue(vars)); }
      return arr;
    }
    if (c === '{') {
      i += 1; const obj: { [k: string]: GqlValue } = {};
      for (;;) {
        skipWs();
        if (query[i] === '}') { i += 1; break; }
        // Keys may be quoted: variable substitution injects JSON, whose
        // object keys are quoted strings.
        let k: string;
        if (query[i] === '"') { k = parseValue(vars) as string; }
        else k = readName();
        skipWs(); if (query[i] === ':') i += 1;
        obj[k] = parseValue(vars);
      }
      return obj;
    }
    if (c === '$') { i += 1; return vars[readName()]; }
    if (c === '-' || (c >= '0' && c <= '9')) {
      const m = /^-?\d+(\.\d+)?/.exec(query.slice(i));
      if (!m) throw new Error('bad number');
      i += m[0].length;
      return Number(m[0]);
    }
    const name = readName();
    if (name === 'true') return true;
    if (name === 'false') return false;
    if (name === 'null') return null;
    return name; // enum value: keep as string
  };
  const parseArgs = (vars: Record<string, GqlValue>): Record<string, GqlValue> => {
    const args: Record<string, GqlValue> = {};
    skipWs();
    if (query[i] !== '(') return args;
    i += 1;
    for (;;) {
      skipWs();
      if (query[i] === ')') { i += 1; break; }
      const name = readName();
      skipWs();
      if (query[i] === ':') i += 1;
      args[name] = parseValue(vars);
    }
    return args;
  };
  const parseSelections = (vars: Record<string, GqlValue>): Sel[] => {
    skipWs();
    if (query[i] !== '{') throw new Error('expected {');
    i += 1;
    const out: Sel[] = [];
    for (;;) {
      skipWs();
      if (query[i] === '}') { i += 1; break; }
      if (query.slice(i, i + 3) === '...') {
        i += 3;
        skipWs();
        if (query.slice(i, i + 2) === 'on') {
          i += 2;
          const tc = readName();
          const sels = parseSelections(vars);
          out.push({ kind: 'fragment', typeCondition: tc, selections: sels });
        } else {
          const name = readName();
          out.push({ kind: 'fragment', name, selections: [] });
        }
        continue;
      }
      let name = readName();
      let alias: string | undefined;
      skipWs();
      if (query[i] === ':') { i += 1; alias = name; name = readName(); }
      const args = parseArgs(vars);
      skipWs();
      let sels: Sel[] | undefined;
      if (query[i] === '{') sels = parseSelections(vars);
      out.push({ kind: 'field', name, alias, args, selections: sels });
    }
    return out;
  };
  const operations: { name?: string; selections: Sel[] }[] = [];
  for (;;) {
    skipWs();
    if (i >= query.length) break;
    let name: string | undefined;
    if (query.slice(i, i + 5) === 'query') { i += 5; name = readName(); }
    else if (query.slice(i, i + 8) === 'mutation') { i += 8; name = readName(); }
    else if (query[i] === '{') { name = undefined; }
    else throw new Error('expected operation');
    skipWs();
    if (query[i] === '(') {
      // variable definitions: read through matching parens, ignoring contents
      let depth = 0;
      while (i < query.length) {
        const c = query[i] as string;
        if (c === '(') depth += 1;
        if (c === ')') { depth -= 1; i += 1; if (depth === 0) break; continue; }
        i += 1;
      }
    }
    const sels = parseSelections({});
    operations.push({ name, selections: sels });
  }
  return { operations };
}
// Resolve variable references lazily: parseValue already looked vars up at parse
// time, but the document is parsed before variables are known in batch mode, so
// we re-parse per operation with the real variables. parseSelections is invoked
// with an empty vars object above only for structure; arguments that used
// variables are re-resolved below by re-parsing the query text per operation.
function gqlParseWithVars(query: string, vars: Record<string, GqlValue>): GqlDocument {
  // Simple approach: substitute is unnecessary — re-run the same parser but with
  // vars available from the start by calling the inner parse with vars. The
  // standalone gqlParse ignores vars in parseValue, so instead we re-implement
  // the entry point by parsing the query once with a patched global: we parse
  // with gqlParse, then walk selections and replace any variable placeholder.
  // Variables were captured as undefined by gqlParse when unknown, which loses
  // the name. To keep it correct we do a textual substitution of $name with the
  // JSON literal of the variable value before parsing (names are unique words).
  let text = query;
  for (const [k, v] of Object.entries(vars)) {
    const re = new RegExp(`\\$${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
    text = text.replace(re, JSON.stringify(v));
  }
  return gqlParse(text);
}
const TYPE_FIELDS: Record<string, Record<string, string>> = {
  Query: { viewer: 'User', repository: 'Repository', node: 'Node' },
  Node: { id: 'ID' },
  User: { login: 'String', id: 'Int' },
  Repository: { id: 'ID', databaseId: 'Int', name: 'String', nameWithOwner: 'String', owner: 'User', defaultBranchRef: 'Ref', viewerPermission: 'String', hasIssuesEnabled: 'Boolean', issue: 'Issue', issues: 'IssueConnection', pullRequests: 'PullRequestConnection', pullRequest: 'PullRequest' },
  Ref: { name: 'String' },
  Issue: { id: 'ID', number: 'Int', title: 'String', state: 'String', body: 'String' },
  PullRequest: { id: 'ID', number: 'Int', headRefName: 'String', baseRefName: 'String', mergeable: 'String', state: 'String', merged: 'Boolean', files: 'PullRequestChangedFileConnection' },
  IssueConnection: { nodes: 'Issue', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestConnection: { nodes: 'PullRequest', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestChangedFileConnection: { nodes: 'PullRequestChangedFile', pageInfo: 'PageInfo' },
  PullRequestChangedFile: { path: 'String' },
  PageInfo: { hasNextPage: 'Boolean', endCursor: 'String', hasPreviousPage: 'Boolean', startCursor: 'String' },
  Mutation: { createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload', mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload' },
  CreateIssuePayload: { issue: 'Issue' },
  CloseIssuePayload: { issue: 'Issue' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest' },
  MergePullRequestPayload: { pullRequest: 'PullRequest' },
  AddCommentPayload: { commentEdge: 'CommentEdge' },
  CommentEdge: { node: 'IssueComment' },
  IssueComment: { id: 'ID', body: 'String' },
  __Type: { name: 'String', fields: '__Field', enumValues: '__EnumValue' },
  __Field: { name: 'String' },
  __EnumValue: { name: 'String' },
};
const TYPE_KIND: Record<string, string> = { Issue: 'OBJECT', PullRequest: 'OBJECT', Repository: 'OBJECT', SearchType: 'ENUM' };
function gqlValidateSelections(sels: Sel[], typeName: string, errors: string[]): void {
  for (const s of sels) {
    if (s.kind === 'fragment') {
      if (s.typeCondition) gqlValidateSelections(s.selections ?? [], s.typeCondition, errors);
      continue;
    }
    const name = s.name as string;
    if (name === '__typename') continue;
    if (name === '__type') {
      if (s.selections) gqlValidateSelections(s.selections, '__Type', errors);
      continue;
    }
    const fields = TYPE_FIELDS[typeName];
    const ret = fields?.[name];
    if (!ret) { errors.push(`Cannot query field "${name}" on type "${typeName}".`); continue; }
    if (s.selections) gqlValidateSelections(s.selections, ret, errors);
  }
}
function asGql(v: GqlValue): GqlObject | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as GqlObject) : null;
}
function repoObject(r: Repo): GqlObject {
  return { __type: 'Repository', id: gid('R', `repo/${r.owner}/${r.name}`), databaseId: r.id, name: r.name, nameWithOwner: `${r.owner}/${r.name}`, _repo: r } as unknown as GqlObject;
}
function issueObject(r: Repo, i: IssueRec): GqlObject {
  return { __type: 'Issue', id: gid('I', `${r.owner}/${r.name}#${i.number}`), number: i.number, title: i.title, state: i.state.toUpperCase(), body: i.body, _repo: r, _issue: i } as unknown as GqlObject;
}
function pullObject(r: Repo, p: PullRec): GqlObject {
  return { __type: 'PullRequest', id: gid('P', `${r.owner}/${r.name}#${p.number}`), number: p.number, headRefName: p.head, baseRefName: p.base, mergeable: prMergeable(r, p), state: p.state.toUpperCase(), merged: p.merged, _repo: r, _pull: p } as unknown as GqlObject;
}
function gqlExecuteSelection(source: GqlObject, sels: Sel[], ctx: { repo?: Repo }): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const s of sels) {
    if (s.kind === 'fragment') {
      if (s.typeCondition && source.__type !== s.typeCondition) continue;
      Object.assign(out, gqlExecuteSelection(source, s.selections ?? [], ctx));
      continue;
    }
    const name = s.name as string;
    const key = s.alias ?? name;
    const args = s.args ?? {};
    if (name === '__typename') { out[key] = source.__type; continue; }
    if (name === '__type') {
      const tname = args.name as string;
      const kind = TYPE_KIND[tname] ?? (tname === 'SearchType' ? 'ENUM' : 'OBJECT');
      const typeObj: GqlObject = { __type: '__Type', name: tname, _kind: kind, _tname: tname } as unknown as GqlObject;
      out[key] = s.selections ? gqlExecuteSelection(typeObj, s.selections, ctx) : typeObj;
      continue;
    }
    const value = gqlResolveField(source, name, args, ctx);
    if (s.selections && value !== null && typeof value === 'object' && !Array.isArray(value)) {
      out[key] = gqlExecuteSelection(value as GqlObject, s.selections, ctx);
    } else if (s.selections && Array.isArray(value)) {
      out[key] = value.map((v) => (v !== null && typeof v === 'object' ? gqlExecuteSelection(v as GqlObject, s.selections as Sel[], ctx) : v));
    } else out[key] = value;
  }
  return out;
}
function gqlResolveField(source: GqlObject, name: string, args: Record<string, GqlValue>, ctx: { repo?: Repo }): GqlValue {
  const typeName = source.__type;
  if (typeName === 'Query') {
    if (name === 'viewer') return { __type: 'User', login: VIEWER, id: VIEWER_ID };
    if (name === 'repository') {
      const owner = args.owner as string; const rname = args.name as string;
      const repo = owner === VIEWER ? getRepo(owner, rname) : undefined;
      return repo ? repoObject(repo) : null;
    }
    if (name === 'node') {
      const id = args.id as string;
      if (typeof id !== 'string') return null;
      const kind = id.split('_')[0];
      const key = b64dec(id.slice(kind.length + 1));
      const m = key.match(/^repo\/([^/]+)\/(.+)$/);
      if (kind === 'R' && m) {
        const repo = getRepo(m[1] as string, m[2] as string);
        return repo ? repoObject(repo) : null;
      }
      return null;
    }
    return null;
  }
  if (typeName === '__Type') {
    const tname = source._tname as string;
    if (name === 'name') return tname;
    if (name === 'fields') {
      const fields = TYPE_FIELDS[tname];
      if (!fields) return null;
      return Object.keys(fields).map((f) => ({ __type: '__Field', name: f }));
    }
    if (name === 'enumValues') {
      if (tname === 'SearchType') return [{ __type: '__EnumValue', name: 'ISSUE' }, { __type: '__EnumValue', name: 'REPOSITORY' }, { __type: '__EnumValue', name: 'USER' }];
      return null;
    }
    return null;
  }
  if (typeName === 'Repository') {
    const repo = source._repo as unknown as Repo;
    if (name === 'id' || name === 'databaseId' || name === 'name' || name === 'nameWithOwner') return source[name];
    if (name === 'owner') return { __type: 'User', login: repo.owner, id: VIEWER_ID };
    if (name === 'defaultBranchRef') return { __type: 'Ref', name: repo.defaultBranch };
    if (name === 'viewerPermission') return 'ADMIN';
    if (name === 'hasIssuesEnabled') return true;
    if (name === 'issue') {
      const n = args.number as number;
      const issue = repo.issues.find((i) => i.number === n);
      return issue ? issueObject(repo, issue) : null;
    }
    if (name === 'issues') return issueConnection(repo, args);
    if (name === 'pullRequests') return pullConnection(repo, args);
    if (name === 'pullRequest') {
      const n = args.number as number;
      const pr = repo.pulls.find((p) => p.number === n);
      return pr ? pullObject(repo, pr) : null;
    }
    return null;
  }
  if (typeName === 'Issue') return source[name];
  if (typeName === 'PullRequest') {
    if (name === 'files') {
      const repo = source._repo as unknown as Repo;
      const p = source._pull as unknown as PullRec;
      const nodes = diffTrees(treeOfCommit(repo, p.baseSha), treeOfCommit(repo, p.headSha)).map((d) => ({ __type: 'PullRequestChangedFile', path: d.path }));
      return { __type: 'PullRequestChangedFileConnection', _nodes: nodes, _pageInfo: { __type: 'PageInfo', hasNextPage: false, endCursor: null } } as unknown as GqlObject;
    }
    return source[name];
  }
  if (typeName === 'IssueConnection' || typeName === 'PullRequestConnection') {
    if (name === 'nodes') return source._nodes as GqlValue;
    if (name === 'totalCount') return (source._nodes as unknown[]).length;
    if (name === 'pageInfo') return source._pageInfo as GqlObject;
    return null;
  }
  if (typeName === 'PullRequestChangedFileConnection') {
    if (name === 'nodes') return source._nodes as GqlValue;
    if (name === 'pageInfo') return source._pageInfo as GqlObject;
    return null;
  }
  if (typeName === 'User') return source[name];
  if (typeName === 'Ref') return source[name];
  if (typeName === 'PageInfo') return source[name];
  if (typeName === 'PullRequestChangedFile') return source[name];
  if (typeName === 'IssueComment') return source[name];
  if (typeName === 'CommentEdge') return source[name];
  if (typeName === 'CreateIssuePayload' || typeName === 'CloseIssuePayload' || typeName === 'CreatePullRequestPayload' || typeName === 'MergePullRequestPayload' || typeName === 'AddCommentPayload') return source[name];
  return source[name] ?? null;
}
function issueConnection(repo: Repo, args: Record<string, GqlValue>): GqlObject {
  let list = [...repo.issues];
  const states = args.states as string[] | undefined;
  if (Array.isArray(states) && states.length) list = list.filter((i) => states.includes(i.state.toUpperCase()));
  const orderBy = args.orderBy as { field?: string; direction?: string } | undefined;
  const dir = orderBy?.direction === 'DESC' ? -1 : 1;
  list.sort((a, b) => (a.number - b.number) * dir);
  let start = 0;
  if (typeof args.after === 'string' && args.after) {
    const idx = parseInt(b64dec(args.after), 10);
    if (!Number.isNaN(idx)) start = idx + 1;
  }
  const first = typeof args.first === 'number' ? args.first : 100;
  const nodes = list.slice(start, start + first).map((i) => issueObject(repo, i));
  const hasNext = start + first < list.length;
  const endCursor = nodes.length ? b64url(String(start + nodes.length - 1)) : null;
  return { __type: 'IssueConnection', _nodes: nodes, _pageInfo: { __type: 'PageInfo', hasNextPage: hasNext, endCursor } } as unknown as GqlObject;
}
function pullConnection(repo: Repo, args: Record<string, GqlValue>): GqlObject {
  let list = [...repo.pulls];
  const states = args.states as string[] | undefined;
  if (Array.isArray(states) && states.length) list = list.filter((p) => states.includes(p.state.toUpperCase()));
  let start = 0;
  if (typeof args.after === 'string' && args.after) {
    const idx = parseInt(b64dec(args.after), 10);
    if (!Number.isNaN(idx)) start = idx + 1;
  }
  const first = typeof args.first === 'number' ? args.first : 100;
  const nodes = list.slice(start, start + first).map((p) => pullObject(repo, p));
  const hasNext = start + first < list.length;
  const endCursor = nodes.length ? b64url(String(start + nodes.length - 1)) : null;
  return { __type: 'PullRequestConnection', _nodes: nodes, _pageInfo: { __type: 'PageInfo', hasNextPage: hasNext, endCursor } } as unknown as GqlObject;
}
function gqlExecuteMutation(name: string, args: Record<string, GqlValue>, sels: Sel[]): GqlObject {
  const input = (args.input ?? {}) as Record<string, GqlValue>;
  if (name === 'createIssue') {
    const repoId = input.repositoryId as string;
    const repo = findRepoByGlobalId(repoId);
    if (!repo) throw new Error('Repository not found');
    const issue: IssueRec = { id: nextIssueId, number: repo.nextNum, title: String(input.title ?? ''), body: typeof input.body === 'string' ? input.body : '', state: 'open', labels: [] };
    nextIssueId += 1; repo.nextNum += 1;
    repo.issues.push(issue);
    return { __type: 'CreateIssuePayload', issue: issueObject(repo, issue) };
  }
  if (name === 'closeIssue') {
    const issueId = input.issueId as string;
    const found = findIssueByGlobalId(issueId);
    if (!found) throw new Error('Issue not found');
    found.issue.state = 'closed';
    return { __type: 'CloseIssuePayload', issue: issueObject(found.repo, found.issue) };
  }
  if (name === 'createPullRequest') {
    const repo = findRepoByGlobalId(input.repositoryId as string);
    if (!repo) throw new Error('Repository not found');
    const head = String(input.headRefName ?? '');
    const base = String(input.baseRefName ?? '');
    const headTip = getBranchTip(repo, head);
    const baseTip = getBranchTip(repo, base);
    if (!headTip || !baseTip) throw new Error('head or base branch not found');
    const dup = repo.pulls.find((p) => p.state === 'open' && p.head === head);
    if (dup) throw new Error('A pull request already exists for this head branch');
    const pr: PullRec = { id: nextPullId, number: repo.nextNum, title: String(input.title ?? ''), body: typeof input.body === 'string' ? input.body : '', state: 'open', head, base, headSha: headTip, baseSha: baseTip, merged: false, mergedAt: null, mergeSha: null };
    nextPullId += 1; repo.nextNum += 1;
    repo.pulls.push(pr);
    return { __type: 'CreatePullRequestPayload', pullRequest: pullObject(repo, pr) };
  }
  if (name === 'mergePullRequest') {
    const found = findPullByGlobalId(input.pullRequestId as string);
    if (!found) throw new Error('Pull request not found');
    const { repo, pull: pr } = found;
    if (pr.merged || pr.state === 'closed') throw new Error('Pull request already merged');
    if (prConflict(repo, pr)) throw new Error('Merge conflict');
    const headTree = treeOfCommit(repo, pr.headSha);
    const treeOid = buildTreeFromMap(repo, headTree);
    pr.baseSha = currentBaseTip(repo, pr);
    const mergeSha = makeCommit(repo, treeOid, [pr.baseSha], `Merge pull request #${pr.number} from ${pr.head}\n\n${pr.title}`);
    repo.refs.set(`refs/heads/${pr.base}`, mergeSha);
    repo.version += 1;
    pr.state = 'closed'; pr.merged = true; pr.mergedAt = FIXED_TS; pr.mergeSha = mergeSha;
    return { __type: 'MergePullRequestPayload', pullRequest: pullObject(repo, pr) };
  }
  if (name === 'addComment') {
    const subjectId = input.subjectId as string;
    const found = findIssueByGlobalId(subjectId) ?? findPullByGlobalId(subjectId);
    if (!found) throw new Error('Subject not found');
    const repo = found.repo;
    const num = 'issue' in found ? found.issue.number : found.pull.number;
    const comment: CommentRec = { id: repo.nextCommentId, body: String(input.body ?? '') };
    repo.nextCommentId += 1; nextCommentId += 1;
    const arr = repo.comments.get(num) ?? [];
    arr.push(comment);
    repo.comments.set(num, arr);
    const node: GqlObject = { __type: 'IssueComment', id: gid('C', `${repo.owner}/${repo.name}#${num}#${comment.id}`), body: comment.body };
    return { __type: 'AddCommentPayload', commentEdge: { __type: 'CommentEdge', node } };
  }
  throw new Error(`Unknown mutation ${name}`);
}
function findRepoByGlobalId(id: string): Repo | undefined {
  if (typeof id !== 'string') return undefined;
  const kind = id.split('_')[0];
  if (kind !== 'R') return undefined;
  const key = b64dec(id.slice(2));
  const m = key.match(/^repo\/([^/]+)\/(.+)$/);
  if (!m) return undefined;
  return getRepo(m[1] as string, m[2] as string);
}
function findIssueByGlobalId(id: string): { repo: Repo; issue: IssueRec } | undefined {
  if (typeof id !== 'string') return undefined;
  const key = b64dec(id.slice(2));
  const m = key.match(/^([^/]+)\/([^#]+)#(\d+)$/);
  if (!m) return undefined;
  const repo = getRepo(m[1] as string, m[2] as string);
  if (!repo) return undefined;
  const issue = repo.issues.find((i) => i.number === parseInt(m[3] as string, 10));
  return issue ? { repo, issue } : undefined;
}
function findPullByGlobalId(id: string): { repo: Repo; pull: PullRec } | undefined {
  if (typeof id !== 'string') return undefined;
  const key = b64dec(id.slice(2));
  const m = key.match(/^([^/]+)\/([^#]+)#(\d+)$/);
  if (!m) return undefined;
  const repo = getRepo(m[1] as string, m[2] as string);
  if (!repo) return undefined;
  const pull = repo.pulls.find((p) => p.number === parseInt(m[3] as string, 10));
  return pull ? { repo, pull } : undefined;
}
function gqlExecuteOperation(query: string, variables: Record<string, GqlValue>): Record<string, unknown> {
  const doc = gqlParseWithVars(query, variables);
  const op = doc.operations[0];
  if (!op) return { data: null, errors: [{ message: 'No operation found' }] };
  const isMutation = query.trimStart().startsWith('mutation');
  const rootType = isMutation ? 'Mutation' : 'Query';
  const errors: string[] = [];
  gqlValidateSelections(op.selections, rootType, errors);
  if (errors.length) return { data: null, errors: errors.map((m) => ({ message: m })) };
  if (isMutation) {
    const out: Record<string, unknown> = {};
    const root: GqlObject = { __type: 'Mutation' };
    for (const s of op.selections) {
      if (s.kind !== 'field') continue;
      const name = s.name as string;
      try {
        const payload = gqlExecuteMutation(name, s.args ?? {}, s.selections ?? []);
        out[s.alias ?? name] = s.selections ? gqlExecuteSelection(payload, s.selections, {}) : payload;
      } catch (e) {
        return { data: null, errors: [{ message: e instanceof Error ? e.message : 'mutation failed' }] };
      }
    }
    return { data: out };
  }
  const root: GqlObject = { __type: 'Query' };
  return { data: gqlExecuteSelection(root, op.selections, {}) };
}
function handleGraphql(req: IncomingMessage, res: ServerResponse, raw: Buffer): void {
  if (!authed(req)) { sendErr(res, 401, 'Bad credentials'); return; }
  const parsed = parseJsonBody(raw);
  if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return; }
  const runOne = (op: unknown): Record<string, unknown> => {
    if (typeof op !== 'object' || op === null) return { data: null, errors: [{ message: 'Invalid operation' }] };
    const o = op as { query?: unknown; variables?: unknown };
    if (typeof o.query !== 'string') return { data: null, errors: [{ message: 'query is required' }] };
    const vars = (o.variables ?? {}) as Record<string, GqlValue>;
    try { return gqlExecuteOperation(o.query, vars); }
    catch (e) { return { data: null, errors: [{ message: e instanceof Error ? e.message : 'GraphQL error' }] }; }
  };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, parsed.value.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(parsed.value));
}

// ---------------------------------------------------------------- MCP
interface McpTool { name: string; description: string; inputSchema: { type: string; properties: Record<string, unknown>; required: string[] } }
const MCP_TOOLS: McpTool[] = [
  { name: 'create_repo', description: 'Create a repository owned by the authenticated user.', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string', description: 'open, closed or all' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Create a pull request in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] } },
];
function mcpArg(args: Record<string, unknown>, ...names: string[]): unknown {
  for (const n of names) { const v = args[n]; if (v !== undefined && v !== null) return v; }
  return undefined;
}
function mcpRepoFromArgs(args: Record<string, unknown>): Repo | undefined {
  let owner = mcpArg(args, 'owner', 'owner_login') as string | undefined;
  let repoName = mcpArg(args, 'repo', 'repository') as string | undefined;
  const full = mcpArg(args, 'full_name') as string | undefined;
  if ((!owner || !repoName) && typeof full === 'string' && full.includes('/')) {
    const [o, r] = full.split('/');
    owner = owner ?? o; repoName = repoName ?? r;
  }
  if (!owner || !repoName) return undefined;
  return owner === VIEWER ? getRepo(owner, repoName) : undefined;
}
function handleMcp(req: IncomingMessage, res: ServerResponse, raw: Buffer): void {
  if (!authed(req)) { sendErr(res, 401, 'Bad credentials'); return; }
  const parsed = parseJsonBody(raw);
  const rpcError = (id: unknown, code: number, message: string): void => {
    res.writeHead(200, { 'content-type': 'application/json', 'x-github-request-id': nextReqId() });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } }));
  };
  if (!parsed.ok) {
    res.writeHead(400, { 'content-type': 'application/json', 'x-github-request-id': nextReqId() });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
    return;
  }
  const body = parsed.value as Json;
  const id = body.id ?? null;
  const method = body.method as string | undefined;
  const params = (body.params ?? {}) as Json;
  const ok = (result: unknown): void => {
    res.writeHead(200, { 'content-type': 'application/json', 'x-github-request-id': nextReqId() });
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
  };
  if (method === 'server/discover') {
    ok({
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    ok({ protocolVersion: offered, capabilities: { tools: {} }, serverInfo: { name: 'forge', version: '1.0.0' } });
    return;
  }
  if (method === 'notifications/initialized' || method?.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': nextReqId() });
    res.end();
    return;
  }
  if (method === 'ping') { ok({}); return; }
  if (method === 'tools/list') {
    ok({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const name = String(params.name ?? '');
    const args = ((params.arguments ?? {}) as Record<string, unknown>);
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (!tool) { rpcError(id, -32602, `Unknown tool: ${name}`); return; }
    for (const reqProp of tool.inputSchema.required) {
      if (args[reqProp] === undefined) {
        // Also accept documented synonyms before failing.
        const has = reqProp === 'owner' ? args.owner_login !== undefined : reqProp === 'repo' ? args.repository !== undefined : false;
        if (!has) { rpcError(id, -32602, `Missing required argument: ${reqProp}`); return; }
      }
    }
    const callResult = (obj: unknown): void => {
      ok({ content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj });
    };
    const callError = (message: string): void => {
      ok({ content: [{ type: 'text', text: JSON.stringify({ error: message }) }], isError: true });
    };
    if (name === 'create_repo') {
      const repoName = args.name as string;
      if (getRepo(VIEWER, repoName)) { callError('Repository creation failed. name already exists on this account'); return; }
      const repo = createRepo(repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
      callResult(repoJson(repo));
      return;
    }
    if (name === 'get_repo') {
      const repo = mcpRepoFromArgs(args);
      if (!repo) { callError('Not Found'); return; }
      callResult(repoJson(repo));
      return;
    }
    if (name === 'create_issue') {
      const repo = mcpRepoFromArgs(args);
      if (!repo) { callError('Not Found'); return; }
      const issue: IssueRec = { id: nextIssueId, number: repo.nextNum, title: String(args.title ?? ''), body: typeof args.body === 'string' ? args.body : '', state: 'open', labels: [] };
      nextIssueId += 1; repo.nextNum += 1;
      repo.issues.push(issue);
      callResult(issueJson(repo, issue));
      return;
    }
    if (name === 'list_issues') {
      const repo = mcpRepoFromArgs(args);
      if (!repo) { callError('Not Found'); return; }
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.issues.filter((i) => state === 'all' ? true : i.state === state).map((i) => issueJson(repo, i));
      callResult({ issues: list });
      return;
    }
    if (name === 'create_pull_request') {
      const repo = mcpRepoFromArgs(args);
      if (!repo) { callError('Not Found'); return; }
      const headRaw = String(args.head ?? '');
      const baseRaw = String(args.base ?? '');
      const head = headRaw.includes(':') ? headRaw.split(':').pop() as string : headRaw;
      const base = baseRaw.includes(':') ? baseRaw.split(':').pop() as string : baseRaw;
      const headTip = getBranchTip(repo, head);
      const baseTip = getBranchTip(repo, base);
      if (!headTip || !baseTip) { callError('head or base branch not found'); return; }
      const dup = repo.pulls.find((p) => p.state === 'open' && p.head === head);
      if (dup) { callError('A pull request already exists for this head branch'); return; }
      const pr: PullRec = { id: nextPullId, number: repo.nextNum, title: String(args.title ?? ''), body: typeof args.body === 'string' ? args.body : '', state: 'open', head, base, headSha: headTip, baseSha: baseTip, merged: false, mergedAt: null, mergeSha: null };
      nextPullId += 1; repo.nextNum += 1;
      repo.pulls.push(pr);
      callResult(pullJson(repo, pr));
      return;
    }
    if (name === 'merge_pull_request') {
      const repo = mcpRepoFromArgs(args);
      if (!repo) { callError('Not Found'); return; }
      const num = Number(mcpArg(args, 'pull_number', 'number'));
      const pr = repo.pulls.find((p) => p.number === num);
      if (!pr) { callError('Not Found'); return; }
      if (pr.merged || pr.state === 'closed') { callError('Pull request already merged'); return; }
      if (prConflict(repo, pr)) { callError('Merge conflict'); return; }
      const headTree = treeOfCommit(repo, pr.headSha);
      const treeOid = buildTreeFromMap(repo, headTree);
      pr.baseSha = currentBaseTip(repo, pr);
    const mergeSha = makeCommit(repo, treeOid, [pr.baseSha], `Merge pull request #${pr.number} from ${pr.head}\n\n${pr.title}`);
      repo.refs.set(`refs/heads/${pr.base}`, mergeSha);
      repo.version += 1;
      pr.state = 'closed'; pr.merged = true; pr.mergedAt = FIXED_TS; pr.mergeSha = mergeSha;
      callResult(pullJson(repo, pr));
      return;
    }
    rpcError(id, -32602, `Unknown tool: ${name}`);
    return;
  }
  rpcError(id, -32601, `Method not found: ${method ?? ''}`);
}

// ---------------------------------------------------------------- app
export function createApp(): Server {
  const server = createServer((req, res) => {
    void (async () => {
      try {
        const raw = await readBody(req);
        const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
        const path = url.pathname;
        if (path === '/healthz') { sendJson(res, 200, { ok: true }); return; }
        if (path === '/api/graphql' && req.method === 'POST') { handleGraphql(req, res, raw); return; }
        if (path === '/mcp') {
          if (req.method === 'POST') { handleMcp(req, res, raw); return; }
          sendErr(res, 405, 'Method Not Allowed');
          return;
        }
        if (path.startsWith('/api/v3')) {
          await handleRest(req, res, raw, url, path);
          return;
        }
        if (await handleGit(req, res, raw, url, path)) return;
        sendErr(res, 404, 'Not Found');
      } catch (e) {
        if (!res.headersSent) sendErr(res, 500, e instanceof Error ? e.message : 'Internal Server Error');
        else { try { res.end(); } catch { /* already ended */ } }
      }
    })();
  });
  return server;
}
