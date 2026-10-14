/**
 * 通用小工具：列名容错取数、数值解析、内置账号白名单、格式化。
 *
 * 为什么要有 `col()`：跨版本列名/大小写会变（真名可能是 `USERNAME`、`USER_NAME` 或别名），
 * 而我们的 SQL 做了降级（最终可能落到 `SELECT *`）。所有取数一律经 `col()`，
 * 这样「列不存在」在检查项里表现为 `undefined`，由检查项自己决定是判 na 还是 unknown，
 * 而不是在 SQL 层炸掉丢掉整条证据。
 */

/** 大小写不敏感取列；支持候选名（按顺序命中第一个有值的）。 */
export function col(row, ...names) {
  if (!row || typeof row !== 'object') return undefined;
  const lower = new Map();
  for (const k of Object.keys(row)) lower.set(k.toUpperCase(), k);
  for (const n of names) {
    const key = lower.get(String(n).toUpperCase());
    if (key === undefined) continue;
    const v = row[key];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  // 全部为空时，返回第一个存在列的原始值（可能是 '' 或 null），保持「列存在但无值」可区分
  for (const n of names) {
    const key = lower.get(String(n).toUpperCase());
    if (key !== undefined) return row[key];
  }
  return undefined;
}

/** 列是否存在（区别于「存在但无值」）。 */
export function hasCol(row, name) {
  if (!row || typeof row !== 'object') return false;
  const up = String(name).toUpperCase();
  return Object.keys(row).some((k) => k.toUpperCase() === up);
}

export function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(String(v).trim());
  return Number.isFinite(n) ? n : null;
}

/**
 * 内置账号白名单。
 *
 * 存在的理由见 DESIGN §2.3：DM 装完就有默认状态（普通版 SYSSSO 非 OPEN、内置账号口令永不过期、
 * 内置账号无资源限制）。不白名单化，新装的库一上手就一片红，报告会直接失去可信度。
 * 白名单只把「内置账号的默认状态」降级为 info；真实状态（失败次数、锁定）照常判定。
 *
 * ⚠️ 安全员账号是 **SYSSSO**（三个 S）—— 2026-10-12 在 10.0.0.40 真机核对纠正：
 *    本插件最初写成 `SYSSO`，导致真机上把 SYSSSO 当成「业务账号」报「已过期」。
 *    `SYSSO` 保留在名单里只是防御性别名，不是达梦的真实账号名。
 */
export const BUILTIN_USERS = ['SYS', 'SYSDBA', 'SYSSSO', 'SYSAUDITOR', 'SYSDBO', 'SYSSO'];

/** 库自身创建的采集账号（如 APPUSER/AWR2），与内置账号同等待遇。 */
const COLLECTOR_RE = /^AWR\d*$/i;

export function isBuiltin(name) {
  const n = String(name ?? '').trim().toUpperCase();
  return BUILTIN_USERS.includes(n) || COLLECTOR_RE.test(n);
}

/** 管理员账号（按三权/四权形态给期望集合）。安全员是 SYSSSO（三个 S）。 */
export const ADMIN_USERS = { SYSDBA: 'DBA', SYSSSO: 'SSO', SYSAUDITOR: 'AUDITOR', SYSDBO: 'DBO' };

/** 名单渲染：超过 n 个就截断，避免报告里出现几百个用户名的墙。 */
export function fmtList(list, n = 12) {
  const arr = [...new Set(list.map((x) => String(x)))].sort();
  if (arr.length <= n) return arr.join('、');
  return `${arr.slice(0, n).join('、')} 等 ${arr.length} 个`;
}

/** 参数值比较用：把 '1'/'ON'/'TRUE' 统一成布尔。 */
export function truthy(v) {
  const s = String(v ?? '').trim().toUpperCase();
  return s === '1' || s === 'ON' || s === 'TRUE' || s === 'Y' || s === 'YES';
}

/**
 * 把「按节点给的参数」拆成列表（主机名、端口、主机密钥，DMDSC 上逐节点给）。
 *
 * ⚠️ `byWhitespace` 默认 `true` —— 主机名与端口这么做没问题，但**主机密钥必须传 `false`**。
 *
 * 为什么：SSH 主机密钥指纹**本身含空格**（`ssh-ed25519 255 SHA256:…`），按空白切会把
 * **一个**指纹拆成 `ssh-ed25519` / `255` / `SHA256:…` 三段，而调用方取的是 `list[0]`
 * —— 正好是 `ssh-ed25519`。plink 于是报
 * `'ssh-ed25519' is not a valid format for a manual host key specification`，
 * 主机侧那 7 项全部落成「未取到」，而报告只会说"SSH 连接失败"，看不出是切分切坏的。
 *
 * 真机实测（2026-10-14，`10.0.0.40`）：Node `spawnSync` 把完整字符串原样传给 plink 时，
 * `ssh-ed25519 255 SHA256:…` 与裸指纹 `SHA256:…` **两种格式 plink 都收** ——
 * 所以问题只在这一处切分，既不在 plink，也不在参数传递。
 * 而那个带空格的格式，**正是本插件文档与提示文案让用户填的那个**。
 *
 * 多节点时主机密钥用**逗号**分隔（见 `sshHostKey` 的参数说明）。
 */
export function splitNodeList(v, { byWhitespace = true } = {}) {
  return String(v ?? '')
    .split(byWhitespace ? /[\s,;]+/ : /[,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
