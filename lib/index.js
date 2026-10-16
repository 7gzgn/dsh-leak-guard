/**
 * dsh-leak-guard — host 入口
 *
 * 一个工具，一件事：**在把东西发出去之前，先看看里面有没有不该出去的凭据。**
 *
 * 挂载一个 `leak_guard` 工具（以及一段系统提示），全部在本地跑：
 * 不联网、不上传、不写盘。发现结果一律脱敏后返回。
 *
 * @module dsh-leak-guard
 */

import { scanPath } from './scanner.js';
import { ruleCatalog, SEVERITY } from './patterns.js';

/** 插件身份。 */
export const name = 'dsh-leak-guard';

/** 需要宿主注入的服务。 */
export const inject = ['tools', 'systemPrompt'];

/** 系统提示段在工具引导带里的排序位。 */
const SECTION_ORDER = 202;

/** 面向模型的公告：插件在场、能干什么、什么时候该用。 */
export const LEAK_GUARD_GUIDANCE = [
  '本机已安装 **dsh-leak-guard**（发布前凭据审计）：提供 `leak_guard` 工具，在**本地**扫描文件/目录里有没有 API key、token、私钥、数据库连接串、明文密码等不该公开的东西，发现结果**脱敏**返回（只留前 6 个字符）。',
  '**什么时候必须用**：把任何东西推到公开仓库 / 发给别人 / 上传之前 —— 尤其是 `git push`、发布 npm 包、把工作区打包外发之前。',
  '用法：`leak_guard({ action: "scan", path: "<目录或文件的绝对路径>" })`，返回 `ok=true` 才算干净；`ok=false` 时先处理 `findings` 里的 critical/high 项再发布。',
  '其它动作：`action:"rules"` 列出全部检测规则；`entropy:true` 额外启用高熵随机串检测（噪声略多，默认关闭）。',
  '它**不联网、不上传任何内容**，只读你指定的路径。',
].join('\n');

/**
 * 动态取 `defineTool`：宿主里有就用真的（带 schema 校验），
 * 单独跑测试时退化成恒等函数，这样核心逻辑可以脱离宿主自测。
 */
let defineTool = (def) => def;
try {
  const mod = await import('@deepseek-ai/dsh-tools');
  if (mod && typeof mod.defineTool === 'function') defineTool = mod.defineTool;
} catch {
  /* 宿主外运行：保持恒等实现 */
}

/** 把发现项压成一行摘要文本。 */
function summarize(result) {
  const { counts, findings, stats } = result;
  const head = result.ok
    ? '✅ 干净：没有发现 critical/high 级凭据'
    : `⛔ 发现 ${counts.critical} 个 critical、${counts.high} 个 high`;
  const lines = [
    head,
    `扫描了 ${stats.filesScanned} 个文件 / ${Math.round(stats.bytesScanned / 1024)} KB，跳过 ${stats.filesSkipped} 个，共 ${counts.total} 条发现。`,
  ];
  const top = findings.slice(0, 20);
  if (top.length > 0) {
    lines.push('');
    for (const f of top) {
      const sev = f.severity === SEVERITY.CRITICAL ? '🔴' : f.severity === SEVERITY.HIGH ? '🟠' : '🟡';
      lines.push(`${sev} ${f.file}${f.line > 0 ? `:${f.line}` : ''} — ${f.label} — ${f.preview}`);
    }
    if (findings.length > top.length) lines.push(`…还有 ${findings.length - top.length} 条，见结构化输出。`);
  }
  if (!result.ok) lines.push('', '**发布前请先处理这些（或确认它们是安全的假阳性）。**');
  return lines.join('\n');
}

/**
 * 挂载插件。
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {{ announceToAgent?: boolean, enabled?: boolean }} [config]
 */
export function apply(ctx, config) {
  const cfg = config ?? {};
  if (cfg.enabled === false) return;

  const disposers = [];

  if (ctx.tools !== undefined && typeof ctx.tools.register === 'function') {
    const definition = defineTool({
      name: 'leak_guard',
      description: [
        '本地凭据审计：在把文件/目录发布出去（git push、发 npm、打包外发）之前，扫描里面有没有 API key、token、私钥、数据库连接串、明文密码等不该公开的秘密。',
        '不联网、不上传；发现结果脱敏（只留匹配串前 6 个字符）。',
        "action='scan'（默认）：扫描 path。返回 ok（true = 没有 critical/high 发现）、counts、findings[]、stats。",
        "action='rules'：列出全部检测规则，不需要 path。",
        'path 建议传绝对路径；不传则退回宿主进程的当前工作目录，通常不是你想要的，所以尽量显式给。',
        'entropy=true 时额外启用高熵随机串检测（只在该行含 key/token/secret 等上下文词时才报，仍可能有个别噪声）。',
        'only 可传扩展名列表（如 ".js,.md"）只扫这些类型。',
      ].join('\n'),
      timeoutMs: 60000,
      parameters: {
        action: {
          type: 'string',
          description: "One of: scan (default), rules. 'scan' 扫路径；'rules' 列出规则表。",
        },
        path: {
          type: 'string',
          description: '要扫描的目录或文件的绝对路径。强烈建议显式传（默认是宿主 cwd）。',
        },
        entropy: {
          type: 'boolean',
          description: '是否启用高熵随机串检测。默认 false。',
        },
        max_findings: {
          type: 'number',
          description: '最多返回多少条发现（默认 200）。',
        },
        only: {
          type: 'string',
          description: '只扫这些扩展名，逗号分隔，例如 ".js,.ts,.md"（默认扫全部文本文件）。',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            action: { type: 'string', required: true },
            ok: { type: 'boolean' },
            counts: { type: 'json' },
            findings: { type: 'json' },
            stats: { type: 'json' },
            rules: { type: 'json' },
            error: { type: 'string' },
          },
        },
        render: (_args, value) => {
          if (typeof value.error === 'string' && value.error !== '') {
            return [{ type: 'text', text: `leak_guard 出错：${value.error}` }];
          }
          if (value.action === 'rules') {
            const list = Array.isArray(value.rules) ? value.rules : [];
            const text = [
              `leak_guard 规则表（${list.length} 条）：`,
              '',
              ...list.map((r) => `- [${r.severity}] ${r.id} — ${r.label}`),
            ].join('\n');
            return [{ type: 'text', text }];
          }
          return [{
            type: 'text',
            text: summarize({
              ok: value.ok === true,
              counts: value.counts ?? { critical: 0, high: 0, medium: 0, total: 0 },
              findings: Array.isArray(value.findings) ? value.findings : [],
              stats: value.stats ?? { filesScanned: 0, filesSkipped: 0, bytesScanned: 0 },
              truncated: false,
            }),
          }];
        },
      },
      async execute(args) {
        const action = ((args && args.action) || 'scan').trim().toLowerCase();

        if (action === 'rules') {
          return { action: 'rules', rules: ruleCatalog() };
        }

        if (action !== 'scan') {
          return { action, error: `unknown action: ${action}（支持 scan / rules）` };
        }

        const target = ((args && args.path) || '').trim() || process.cwd();
        const only = typeof args?.only === 'string' && args.only.trim() !== ''
          ? args.only.split(',').map((s) => s.trim()).filter(Boolean)
          : undefined;

        try {
          const result = await scanPath(target, {
            entropy: args?.entropy === true,
            maxFindings: typeof args?.max_findings === 'number' && args.max_findings > 0
              ? Math.min(Math.round(args.max_findings), 2000)
              : undefined,
            only,
          });
          return {
            action: 'scan',
            ok: result.ok,
            counts: result.counts,
            findings: result.findings,
            stats: result.stats,
          };
        } catch (err) {
          return { action: 'scan', error: err instanceof Error ? err.message : String(err) };
        }
      },
    });

    disposers.push(ctx.tools.register(definition));
  }

  if (cfg.announceToAgent !== false && ctx.systemPrompt !== undefined
    && typeof ctx.systemPrompt.section === 'function') {
    disposers.push(ctx.systemPrompt.section({
      name: 'plugin:leak-guard',
      order: SECTION_ORDER,
      text: LEAK_GUARD_GUIDANCE,
    }));
  }

  if (typeof ctx.effect === 'function' && disposers.length > 0) {
    ctx.effect(() => () => {
      for (const dispose of disposers) {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          /* 卸载失败不阻断其它清理 */
        }
      }
    }, 'dsh-leak-guard: teardown');
  }
}
