/**
 * dsh-leak-guard — 凭据模式库
 *
 * 设计原则：宁可漏报，不要误报。
 * 每条规则都要求「特异前缀 + 足够长的随机体」，这样文档里的
 * `sk-xxxx`、`your_api_key_here` 这类占位符不会被当成真凭据。
 *
 * 零依赖：只用标准 JS，不引入任何第三方包。
 */

/** 严重级别。critical = 提交上去就等于泄露；high = 高度可疑；medium = 需要人看一眼。 */
export const SEVERITY = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
});

/**
 * 占位符白名单：命中它的匹配一律丢弃。
 * 覆盖 `sk-xxxxxxxx`、`<YOUR_KEY>`、`${TOKEN}`、`change-me`、`redacted` 等常见写法。
 * 另外放过**文档惯例的示例账号对**（`user:pass`、`username:password`、`admin:pwd`…）——
 * 这类写法在 README 里是标准占位，本身也不构成有效凭据；不放它，每个写文档的人
 * 都会收到一条假警报（这个分支就是被自己的 README 报出来的）。
 */
export const PLACEHOLDER_RE =
  /(x{4,}|y{4,}|\*{4,}|your[_-]?(api[_-]?)?(key|token|secret|password)|my[_-]?(key|token|secret)|example|sample|placeholder|dummy|fake|test[_-]?key|redacted|changeme|change[_-]?me|<[^>]{1,40}>|\$\{[^}]{1,40}\}|%[A-Z_]{1,30}%|\.{3,}|…|待填|填写|替换|\b(user(name)?|admin|root|test|foo|john|jane):(pass(word)?|pwd|secret|123456?)\b)/i;

/**
 * 敏感文件名模式（相对路径，正斜杠形式）。
 * 这类文件即便里面没匹配到具体规则，也应该被点名——它们几乎不该出现在公开仓库里。
 */
export const SENSITIVE_FILE_PATTERNS = [
  { id: 'dotenv', label: '.env 环境变量文件', regex: /(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/ },
  { id: 'dsh-credentials', label: 'DSH 凭据文件', regex: /(^|\/)\.credentials\.ya?ml$/ },
  { id: 'loose-token-file', label: '裸 token 文件', regex: /(^|\/)(\.gh-token|\.npm-token|\.pypi-token|token|tokens)\.(txt|json|ya?ml)?$/ },
  { id: 'git-credentials', label: 'git 明文凭据', regex: /(^|\/)\.git-credentials$/ },
  { id: 'npmrc', label: 'npm 配置（可能含 _authToken）', regex: /(^|\/)\.npmrc$/ },
  { id: 'netrc', label: 'netrc 明文凭据', regex: /(^|\/)\.netrc$/ },
  { id: 'ssh-private-key', label: 'SSH 私钥', regex: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/ },
  { id: 'key-file', label: '私钥/证书文件', regex: /\.(pem|key|p12|pfx|jks|keystore|ppk)$/i },
  { id: 'gcloud-key', label: 'GCP 服务账号密钥', regex: /service[-_]?account[^/]*\.json$/i },
  { id: 'aws-credentials', label: 'AWS 凭据文件', regex: /(^|\/)\.aws\/credentials$/ },
  { id: 'kubeconfig', label: 'kubeconfig', regex: /(^|\/)(kubeconfig|\.kube\/config)$/ },
];

/**
 * 内容规则表。
 * `regex` 必须带 g 标志；扫描器会在每个文件行上重新构造后使用，避免 lastIndex 污染。
 */
export const RULES = [
  // ── 大模型 / AI 服务 ───────────────────────────────────────────
  {
    id: 'llm-api-key',
    label: 'LLM API key（sk- 前缀）',
    severity: SEVERITY.CRITICAL,
    regex: /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  },
  {
    id: 'anthropic-key',
    label: 'Anthropic API key',
    severity: SEVERITY.CRITICAL,
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: 'huggingface-token',
    label: 'HuggingFace token',
    severity: SEVERITY.CRITICAL,
    regex: /\bhf_[A-Za-z0-9]{25,}\b/g,
  },

  // ── 代码托管 ──────────────────────────────────────────────────
  {
    id: 'github-token',
    label: 'GitHub token（ghp_/gho_/ghu_/ghs_/ghr_）',
    severity: SEVERITY.CRITICAL,
    regex: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
  },
  {
    id: 'github-pat-fine-grained',
    label: 'GitHub fine-grained PAT',
    severity: SEVERITY.CRITICAL,
    regex: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g,
  },
  {
    id: 'gitlab-token',
    label: 'GitLab token',
    severity: SEVERITY.CRITICAL,
    regex: /\bglpat-[A-Za-z0-9_-]{18,}\b/g,
  },
  {
    id: 'gitee-token',
    label: 'Gitee 私人令牌',
    severity: SEVERITY.HIGH,
    regex: /\b[0-9a-f]{32}\b(?=[^\n]{0,40}(gitee|私人令牌|access[_-]?token))/gi,
  },

  // ── 云厂商 ────────────────────────────────────────────────────
  {
    id: 'aws-access-key-id',
    label: 'AWS Access Key ID',
    severity: SEVERITY.CRITICAL,
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: 'aliyun-access-key',
    label: '阿里云 AccessKey',
    severity: SEVERITY.CRITICAL,
    regex: /\bLTAI[A-Za-z0-9]{12,}\b/g,
  },
  {
    id: 'tencent-secret-id',
    label: '腾讯云 SecretId',
    severity: SEVERITY.HIGH,
    regex: /\bAKID[A-Za-z0-9]{13,}\b/g,
  },
  {
    id: 'google-api-key',
    label: 'Google API key',
    severity: SEVERITY.CRITICAL,
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: 'azure-key',
    label: 'Azure / 通用 88 位 base64 密钥',
    severity: SEVERITY.MEDIUM,
    regex: /\b[A-Za-z0-9+/]{86}==\b/g,
  },

  // ── 支付 / 通信 ───────────────────────────────────────────────
  {
    id: 'stripe-secret',
    label: 'Stripe secret key',
    severity: SEVERITY.CRITICAL,
    regex: /\bsk_(live|test)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    severity: SEVERITY.CRITICAL,
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    id: 'telegram-bot-token',
    label: 'Telegram bot token',
    severity: SEVERITY.CRITICAL,
    regex: /\b\d{8,12}:AA[A-Za-z0-9_-]{30,}\b/g,
  },
  {
    id: 'sendgrid-key',
    label: 'SendGrid API key',
    severity: SEVERITY.CRITICAL,
    regex: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
  },

  // ── 私钥 / 证书 ───────────────────────────────────────────────
  {
    id: 'private-key-block',
    label: '私钥内容块',
    severity: SEVERITY.CRITICAL,
    regex: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'jwt',
    label: 'JWT（可能含身份声明，视场景而定）',
    severity: SEVERITY.MEDIUM,
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },

  // ── 连接串 / 通用赋值 ─────────────────────────────────────────
  {
    id: 'db-connection-string',
    label: '带密码的数据库连接串',
    severity: SEVERITY.CRITICAL,
    regex: /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql|clickhouse):\/\/[^\s:@/]{1,64}:[^\s:@/]{3,128}@/gi,
  },
  {
    id: 'assignment-secret',
    label: '硬编码的秘密赋值（password/secret/token/api_key = "…"）',
    severity: SEVERITY.HIGH,
    regex: /\b(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"`]([^'"`\n]{8,200})['"`]/gi,
  },
  {
    id: 'bearer-token',
    label: '硬编码 Bearer token',
    severity: SEVERITY.HIGH,
    regex: /\bBearer\s+[A-Za-z0-9\-._~+/]{25,}=*/g,
  },
  {
    id: 'basic-auth-url',
    label: 'URL 内嵌用户名密码',
    severity: SEVERITY.HIGH,
    regex: /\bhttps?:\/\/[^\s:@/]{1,64}:[^\s:@/]{3,128}@[^\s/]+/gi,
  },
];

/** 概览用的规则清单（不含正则，供 `rules` 动作输出）。 */
export function ruleCatalog() {
  return RULES.map((r) => ({ id: r.id, label: r.label, severity: r.severity }));
}

/** 高熵检测：找「看起来像随机密钥」的长串。默认只作为 medium 提示。 */
export const ENTROPY_MIN_LENGTH = 32;

/** 计算字符串的香农熵（bit/char）。 */
export function shannonEntropy(text) {
  if (text.length === 0) return 0;
  const freq = new Map();
  for (const ch of text) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / text.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** 高熵候选的整体形态：连续的可疑字符集片段。 */
export const ENTROPY_CANDIDATE_RE = /[A-Za-z0-9+/_=-]{32,}/g;
