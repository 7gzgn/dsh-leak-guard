/**
 * 自己扫自己：对 dsh-leak-guard 的源码目录跑一遍它自己的扫描器。
 *
 * 这是「谁来看守看守者」的最小答案 —— 至少让规则在自己身上过一遍。
 * 用法：node test/self-scan.mjs
 */

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scanPath } from '../lib/scanner.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const result = await scanPath(root, { entropy: false });

console.log(`扫描目录：${root}`);
console.log(`ok = ${result.ok}`);
console.log(`counts = ${JSON.stringify(result.counts)}`);
console.log(`stats  = ${JSON.stringify(result.stats)}`);
for (const f of result.findings) {
  console.log(`  - [${f.severity}] ${f.file}${f.line ? `:${f.line}` : ''} ${f.rule} ${f.preview}`);
}
process.exit(result.ok ? 0 : 1);
