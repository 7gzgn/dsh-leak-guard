/**
 * dsh-leak-guard — 扫描引擎
 *
 * 走目录树、读文本、按模式库找凭据。没有依赖，没有网络，没有遥测：
 * 它只读你给它的路径，然后把发现**脱敏**后返回。
 *
 * 关键设计：
 *  - 先用一条「快速预筛」正则过滤掉绝大多数无关行，只有疑似行才跑完整规则（性能）；
 *  - 命中占位符白名单（sk-xxxx / <YOUR_KEY> / ${TOKEN} …）直接丢弃（精度）；
 *  - 预览一律脱敏，只留前 6 个字符（安全）。
 */

import { lstat, readdir, readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import {
  RULES,
  SENSITIVE_FILE_PATTERNS,
  PLACEHOLDER_RE,
  SEVERITY,
  ENTROPY_CANDIDATE_RE,
  ENTROPY_MIN_LENGTH,
  shannonEntropy,
} from './patterns.js';

/** 默认跳过的目录名（大小写不敏感）。 */
export const DEFAULT_SKIP_DIRS = [
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', '.cache', '.parcel-cache', '.turbo', '.venv', 'venv',
  '__pycache__', '.idea', '.vs', 'target', 'vendor', '.gradle', '.terraform',
];

/** 默认跳过的扩展名（二进制 / 归档，扫了也是浪费时间）。 */
export const DEFAULT_SKIP_EXTS = [
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.svgz',
  '.mp3', '.mp4', '.mov', '.avi', '.wav', '.flac', '.webm',
  '.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.jar', '.war',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.pyc', '.o', '.a',
  '.woff', '.woff2', '.ttf', '.otf', '.eot', '.pdf', '.docx', '.xlsx',
  '.pptx', '.sqlite', '.db', '.i64', '.idb', '.asar', '.node',
];

const DEFAULT_MAX_BYTES = 1024 * 1024; // 单文件 1MB 上限
const DEFAULT_MAX_FINDINGS = 200;
const HARD_LINE_LIMIT = 20000;

/**
 * 快速预筛：命中它的行才值得跑完整规则。
 * 必须覆盖所有规则的「最小可辨识特征」，宁可宽一点。
 */
const QUICK_RE = new RegExp(
  [
    'sk-', 'gh[pousr]_', 'github_pat_', 'glpat-', 'hf_',
    'AKIA', 'ASIA', 'LTAI', 'AKID', 'AIza',
    'xox', 'SG\\.', '-----BEGIN', 'eyJ', 'Bearer\\s',
    'password', 'passwd', 'pwd', 'secret', 'token', 'api[_-]?key',
    'access[_-]?key', 'private[_-]?key', 'client[_-]?secret',
    '(postgres(ql)?|mysql|mongodb(\\+srv)?|redis|amqp|mssql|clickhouse)://',
    '://[^\\s]{0,120}@',
    '密钥', '令牌', '密码',
  ].join('|'),
  'i',
);

/**
 * 「泛化」规则：它们命中面广、容易和具体规则重复报同一处。
 * 策略——同一行只要已有具体规则命中，就跳过这些，避免一条泄露报两遍。
 */
const GENERIC_RULE_IDS = new Set(['assignment-secret', 'bearer-token']);

const SPECIFIC_RULES = RULES.filter((r) => !GENERIC_RULE_IDS.has(r.id));
const GENERIC_RULES = RULES.filter((r) => GENERIC_RULE_IDS.has(r.id));

/** 在一行里跑一组规则，把命中推进 `out`。 */
function runRules(rules, line, relPath, lineNo, out) {
  for (const rule of rules) {
    const re = new RegExp(rule.regex.source, rule.regex.flags);
    let m;
    while ((m = re.exec(line)) !== null) {
      const raw = m[0];
      if (m.index === re.lastIndex) re.lastIndex += 1;
      if (raw.length === 0) continue;
      if (PLACEHOLDER_RE.test(raw)) continue;
      out.push({
        file: relPath,
        line: lineNo,
        rule: rule.id,
        label: rule.label,
        severity: rule.severity,
        preview: redact(raw),
      });
    }
  }
}

/** 高熵候选必须同时具备的「上下文词」，否则不报（压误报）。 */
const ENTROPY_CONTEXT_RE = /(key|token|secret|password|passwd|pwd|credential|auth|密钥|令牌|密码)/i;

/** 路径转正斜杠，便于跨平台匹配。 */
function toPosix(p) {
  return p.split(sep).join('/');
}

/** 只留前 6 个字符的脱敏预览。 */
export function redact(match) {
  const head = match.slice(0, 6);
  return `${head}…（${match.length} 字符）`;
}

/** 粗略的二进制判定：前 8KB 里存在 NUL 就当二进制。 */
function looksBinary(buf) {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i += 1) {
    if (buf[i] === 0) return true;
  }
  return false;
}

/** 文件名是否命中敏感文件清单。 */
export function matchSensitiveFile(relPath) {
  const posix = toPosix(relPath);
  const hits = [];
  for (const p of SENSITIVE_FILE_PATTERNS) {
    if (p.regex.test(posix)) hits.push({ id: p.id, label: p.label });
  }
  return hits;
}

/**
 * 扫一段文本，返回发现项。
 * @param {string} text 文件内容
 * @param {string} relPath 相对路径（用于报告）
 * @param {{entropy?: boolean}} opts
 */
export function scanText(text, relPath, opts = {}) {
  const findings = [];
  const lines = text.split(/\r?\n/).slice(0, HARD_LINE_LIMIT);

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.length === 0 || line.length > 5000) continue;
    if (!QUICK_RE.test(line) && !ENTROPY_CANDIDATE_RE.test(line)) {
      ENTROPY_CANDIDATE_RE.lastIndex = 0;
      continue;
    }

    // 先跑具体规则；这一行已经有具体命中时，泛化规则让位（同一条泄露不报两遍）
    const hits = [];
    runRules(SPECIFIC_RULES, line, relPath, i + 1, hits);
    if (hits.length === 0) runRules(GENERIC_RULES, line, relPath, i + 1, hits);
    findings.push(...hits);

    if (opts.entropy === true && ENTROPY_CONTEXT_RE.test(line)) {
      const re = new RegExp(ENTROPY_CANDIDATE_RE.source, 'g');
      let m;
      while ((m = re.exec(line)) !== null) {
        const raw = m[0];
        if (raw.length < ENTROPY_MIN_LENGTH) continue;
        if (PLACEHOLDER_RE.test(raw)) continue;
        if (shannonEntropy(raw) < 4.5) continue;
        // 已经由具体规则报过的，不重复报
        if (findings.some((f) => f.line === i + 1 && f.preview.startsWith(raw.slice(0, 6)))) continue;
        findings.push({
          file: relPath,
          line: i + 1,
          rule: 'high-entropy-string',
          label: '高熵随机串（疑似密钥，需人工确认）',
          severity: SEVERITY.MEDIUM,
          preview: redact(raw),
        });
      }
    }
  }

  return findings;
}

/** 严重度排序权重。 */
const SEV_ORDER = { [SEVERITY.CRITICAL]: 0, [SEVERITY.HIGH]: 1, [SEVERITY.MEDIUM]: 2 };

/** 归一化并排序发现项。 */
export function sortFindings(findings) {
  return findings.slice().sort((a, b) => {
    const s = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
    if (s !== 0) return s;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });
}

/**
 * 扫描一个文件或目录。
 * @param {string} target 绝对路径
 * @param {object} [options]
 * @param {boolean} [options.entropy] 是否启用高熵检测（默认 false）
 * @param {number}  [options.maxBytes] 单文件大小上限
 * @param {number}  [options.maxFindings] 发现项上限
 * @param {string[]} [options.skipDirs] 追加跳过的目录名
 * @param {string[]} [options.only] 只扫这些扩展名（如 ['.js','.md']）
 */
export async function scanPath(target, options = {}) {
  const opts = {
    entropy: options.entropy === true,
    maxBytes: options.maxBytes ?? DEFAULT_MAX_BYTES,
    maxFindings: options.maxFindings ?? DEFAULT_MAX_FINDINGS,
    skipDirs: new Set([...DEFAULT_SKIP_DIRS, ...(options.skipDirs ?? [])].map((s) => s.toLowerCase())),
    skipExts: new Set(DEFAULT_SKIP_EXTS),
    only: Array.isArray(options.only) && options.only.length > 0
      ? new Set(options.only.map((e) => (e.startsWith('.') ? e.toLowerCase() : `.${e.toLowerCase()}`)))
      : null,
  };

  const findings = [];
  const stats = { filesScanned: 0, filesSkipped: 0, bytesScanned: 0, dirsVisited: 0 };
  const base = target;

  async function walk(absPath) {
    if (findings.length >= opts.maxFindings) return;
    let st;
    try {
      st = await lstat(absPath);
    } catch {
      stats.filesSkipped += 1;
      return;
    }
    if (st.isSymbolicLink()) return; // 不跟随符号链接

    if (st.isDirectory()) {
      const name = absPath.slice(absPath.lastIndexOf(sep) + 1).toLowerCase();
      if (absPath !== base && opts.skipDirs.has(name)) return;
      stats.dirsVisited += 1;
      let entries;
      try {
        entries = await readdir(absPath);
      } catch {
        return;
      }
      for (const entry of entries) {
        if (findings.length >= opts.maxFindings) return;
        await walk(join(absPath, entry));
      }
      return;
    }

    if (!st.isFile()) return;

    const relPath = toPosix(relative(base, absPath)) || absPath.slice(absPath.lastIndexOf(sep) + 1);

    // 敏感文件名：不管内容如何，先记一笔
    const nameHits = matchSensitiveFile(relPath);
    for (const hit of nameHits) {
      findings.push({
        file: relPath,
        line: 0,
        rule: `file:${hit.id}`,
        label: `敏感文件：${hit.label}`,
        severity: SEVERITY.HIGH,
        preview: '(文件名命中，未读取内容)',
      });
    }

    const dot = absPath.lastIndexOf('.');
    const ext = dot > 0 ? absPath.slice(dot).toLowerCase() : '';
    if (opts.only !== null && !opts.only.has(ext)) {
      stats.filesSkipped += 1;
      return;
    }
    if (opts.skipExts.has(ext)) {
      stats.filesSkipped += 1;
      return;
    }
    if (st.size > opts.maxBytes) {
      stats.filesSkipped += 1;
      findings.push({
        file: relPath,
        line: 0,
        rule: 'skipped:too-large',
        label: `文件超过 ${Math.round(opts.maxBytes / 1024)}KB，未扫描内容`,
        severity: SEVERITY.MEDIUM,
        preview: `${Math.round(st.size / 1024)} KB`,
      });
      return;
    }

    let buf;
    try {
      buf = await readFile(absPath);
    } catch {
      stats.filesSkipped += 1;
      return;
    }
    if (looksBinary(buf)) {
      stats.filesSkipped += 1;
      return;
    }

    stats.filesScanned += 1;
    stats.bytesScanned += buf.length;
    findings.push(...scanText(buf.toString('utf8'), relPath, opts));
  }

  await walk(target);

  const deduped = [];
  const seen = new Set();
  for (const f of sortFindings(findings)) {
    const k = `${f.file}|${f.line}|${f.rule}|${f.preview}`;
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(f);
  }

  const blocked = deduped.filter(
    (f) => f.severity === SEVERITY.CRITICAL || f.severity === SEVERITY.HIGH,
  );

  return {
    target,
    ok: blocked.length === 0,
    findings: deduped.slice(0, opts.maxFindings),
    truncated: deduped.length > opts.maxFindings,
    counts: {
      critical: deduped.filter((f) => f.severity === SEVERITY.CRITICAL).length,
      high: deduped.filter((f) => f.severity === SEVERITY.HIGH).length,
      medium: deduped.filter((f) => f.severity === SEVERITY.MEDIUM).length,
      total: deduped.length,
    },
    stats,
  };
}
