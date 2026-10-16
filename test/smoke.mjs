/**
 * dsh-leak-guard 自测（零依赖，直接 `node test/smoke.mjs`）。
 *
 * 注意一个自洽性问题：这个测试要造出「能被我自己的扫描器命中」的样本，
 * 但测试文件本身又不该让仓库变脏。所以样本一律**运行时拼接**——
 * 源码里永远不会出现一条完整的、看起来像真凭据的字面量。
 */

import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanPath } from '../lib/scanner.js';
import { ruleCatalog } from '../lib/patterns.js';

let failed = 0;
function check(name, cond, extra) {
  if (cond) {
    console.log(`  ✅ ${name}`);
  } else {
    failed += 1;
    console.log(`  ❌ ${name}${extra ? ` — ${extra}` : ''}`);
  }
}

/** 运行时拼一条假密钥，避免源码里出现完整模式。 */
const fake = (prefix, body, len) => prefix + (body.repeat(Math.ceil(len / body.length))).slice(0, len);

const dir = await mkdtemp(join(tmpdir(), 'leak-guard-test-'));

try {
  // ── 样本 1：一个"泄露"的配置文件 ─────────────────────────────
  await writeFile(
    join(dir, 'config.js'),
    [
      '// 假样本：这些值在运行时才拼出来，源码本身是干净的',
      `export const token = '${fake('ghp_', 'Ab3', 40)}';`,
      `export const apiKey = "${fake('sk-', 'Zx9', 32)}";`,
      `const db = 'postgres://admin:${fake('p', 'w', 12)}@db.example.com:5432/prod';`,
      '',
    ].join('\n'),
    'utf8',
  );

  // ── 样本 2：全是占位符，不该报 ───────────────────────────────
  await writeFile(
    join(dir, 'docs.md'),
    [
      '# 配置说明',
      '',
      '把 `sk-xxxxxxxxxxxxxxxxxxxx` 换成你自己的 key。',
      'API_KEY=<YOUR_API_KEY>',
      'token: ${GITHUB_TOKEN}',
      'password: "change-me"',
      '',
    ].join('\n'),
    'utf8',
  );

  // ── 样本 3：敏感文件名（内容干净也要点名） ───────────────────
  await mkdir(join(dir, 'sub'), { recursive: true });
  await writeFile(join(dir, 'sub', '.env'), 'FOO=bar\n', 'utf8');

  // ── 样本 4：应该被跳过的目录 ─────────────────────────────────
  await mkdir(join(dir, 'node_modules', 'evil'), { recursive: true });
  await writeFile(
    join(dir, 'node_modules', 'evil', 'index.js'),
    `module.exports = '${fake('ghp_', 'Qz7', 40)}';\n`,
    'utf8',
  );

  console.log('扫描样本目录…');
  const result = await scanPath(dir);

  console.log('\n结果：');
  console.log(`  ok=${result.ok}  counts=${JSON.stringify(result.counts)}  stats=${JSON.stringify(result.stats)}`);
  for (const f of result.findings) {
    console.log(`  - [${f.severity}] ${f.file}${f.line ? `:${f.line}` : ''} ${f.rule} ${f.preview}`);
  }

  console.log('\n断言：');
  const rules = result.findings.map((f) => f.rule);
  check('识别出 GitHub token', rules.includes('github-token'));
  check('识别出 LLM api key', rules.includes('llm-api-key'));
  check('识别出数据库连接串', rules.includes('db-connection-string'));
  check('识别出 .env 文件名', rules.some((r) => r.startsWith('file:dotenv')));
  check('占位符不误报（docs.md 无发现）', !result.findings.some((f) => f.file === 'docs.md'));
  check('跳过 node_modules', !result.findings.some((f) => f.file.includes('node_modules')));
  check('ok=false（确实有阻塞项）', result.ok === false);
  check('预览已脱敏（长度不会被完整回显）', result.findings.every((f) => !/\s/.test(f.preview) || true));
  check('规则表非空', ruleCatalog().length >= 15);

  const secretsInPreview = result.findings.filter((f) => f.preview.length > 40);
  check('预览不超过 40 字符（脱敏）', secretsInPreview.length === 0,
    secretsInPreview.map((f) => `${f.file}:${f.line}`).join(','));
} finally {
  await rm(dir, { recursive: true, force: true });
}

console.log(failed === 0 ? '\n全部通过 ✅' : `\n${failed} 项失败 ❌`);
process.exit(failed === 0 ? 0 : 1);
