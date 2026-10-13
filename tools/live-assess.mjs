/**
 * 真机验证脚本（连真实达梦库，只读）。
 *
 * 用法：
 *   node tools/live-assess.mjs 10.0.0.40:5236 --secret-file <口令文件>
 *   node tools/live-assess.mjs 10.0.0.40:5236 --secret-env DM_SECURITY_PASSWORD
 *   node tools/live-assess.mjs 10.0.0.40:5236 --secret-file <口令文件> --level 2   # 等保对照级别（默认 3）
 *
 * 主机侧（P2，可选）—— 与数据库口令同一套纪律：只从文件 / 环境变量读，绝不进命令行：
 *   --ssh-user dmdba --ssh-secret-file <SSH 口令文件>   # 同时给才启用；再加 --ssh-host/--ssh-port/--ssh-host-key
 *   不启用时那 7 项检查判「不适用」，插件保持纯 JDBC 只读。
 *
 * 口令来源（按顺序）：
 *   --secret-file <path>   从文件读第一行（**推荐**：不把口令带进命令行/会话日志）
 *   --secret-env <NAME>    从环境变量读（默认 DM_SECURITY_PASSWORD）
 *
 * 本脚本只做三件事：
 *   1. 按插件的 22 条只读查询采集一次，**打印每条查询的真实列名**（这是 DESIGN §8「待核实清单」要的东西）；
 *   2. 跑完整判定，打印六态分布与「未取到/不适用」的原因；
 *   3. 落盘一份真实 HTML 报告 + 一份 JSON findings（供回填 DESIGN）。
 *
 * 安全：口令只在内存里传给 Java 桥，**不进任何输出**；脚本结束前会自查
 *      「输出里是否出现口令」，出现就直接报错退出（防止以后改代码时意外泄漏）。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');

const load = (rel) => import(pathToFileURL(path.join(PKG, rel)).href);
const argv = process.argv.slice(2);

function arg(name, def = null) {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : def;
}

const target = argv.find((a) => !a.startsWith('--') && /:\d+$/.test(a)) ?? arg('target', '10.0.0.40:5236');
const [host, portStr] = target.split(':');
const port = Number(portStr || 5236);
const user = arg('user', 'SYSDBA');
/**
 * 连接账号实际具备的权限层。检查项的 `priv` 是「拿数据所需的最小权限」，
 * 若连接账号不是 SYSDBA，理论上应判 unknown；但真机验证时更需要看到**数据驱动的真实结论**，
 * 所以这里可以显式声明（默认 SYSDBA），并在输出里标明连接账号，避免把 APPUSER 的评估
 * 当成 SYSDBA 的评估来读。
 */
const privs = String(arg('privs', 'SYSDBA')).split(',').map((s) => s.trim()).filter(Boolean);
const home = arg('home', path.join(PKG, '..', '.dm-home'));
const outDir = arg('out', path.join(PKG, '..', 'dm-security-reports'));
/** 等保对照级别（2/3/4，默认 3）：决定条款编号与「高等级专属条款是否判不适用」。 */
const { COMPLIANCE_LEVELS, DEFAULT_COMPLIANCE_LEVEL, levelMeta } = await load('lib/compliance.js');
const levelRaw = Number(arg('level', DEFAULT_COMPLIANCE_LEVEL));
const level = COMPLIANCE_LEVELS.includes(levelRaw) ? levelRaw : DEFAULT_COMPLIANCE_LEVEL;

/** 口令来源。任何一条都不打印口令本身。 */
function loadSecret() {
  const file = arg('secret-file');
  if (file) {
    const p = file.startsWith('~') ? path.join(os.homedir(), file.slice(2)) : file;
    if (!fs.existsSync(p)) throw new Error(`口令文件不存在：${p}`);
    const v = fs.readFileSync(p, 'utf8').split(/\r?\n/)[0].trim();
    if (!v) throw new Error(`口令文件为空：${p}`);
    return { value: v, source: `文件 ${p}` };
  }
  const envName = arg('secret-env', 'DM_SECURITY_PASSWORD');
  const v = process.env[envName];
  if (v) return { value: v, source: `环境变量 ${envName}` };
  throw new Error(
    '未取得口令。请用 --secret-file <路径>（推荐，不进命令行）或 --secret-env <变量名> 提供。\n' +
      '注意：不要用 --password 之类的命令行参数，那会进 shell 历史与进程列表。',
  );
}

/**
 * SSH 口令来源（主机侧 P2）。与数据库口令**同一套纪律**：只从文件或环境变量读，
 * 不接受 `--ssh-password`（那会进 shell 历史与进程列表），也绝不打印。
 */
function loadSshSecret() {
  const file = arg('ssh-secret-file');
  if (file) {
    const p = file.startsWith('~') ? path.join(os.homedir(), file.slice(2)) : file;
    if (!fs.existsSync(p)) throw new Error(`SSH 口令文件不存在：${p}`);
    const v = fs.readFileSync(p, 'utf8').split(/\r?\n/)[0].trim();
    if (!v) throw new Error(`SSH 口令文件为空：${p}`);
    return { value: v, source: `文件 ${p}` };
  }
  const envName = arg('ssh-secret-env', 'DM_SECURITY_SSH_PASSWORD');
  const v = process.env[envName];
  if (v) return { value: v, source: `环境变量 ${envName}` };
  return { value: null, source: '未提供（本次不做主机侧检查）' };
}

const secret = loadSecret();
/** 主机侧采集配置：`--ssh-user` 与口令**同时给出**才启用（与插件内的口径一致）。 */
const sshSecret = loadSshSecret();
const sshUser = arg('ssh-user');
const ssh =
  sshUser && sshSecret.value
    ? {
        host: arg('ssh-host', host),
        port: Number(arg('ssh-port', 22)),
        user: sshUser,
        password: sshSecret.value,
        hostKey: arg('ssh-host-key'),
        plinkPath: arg('plink-path', 'plink'),
      }
    : null;
const osRetentionDays = Number(arg('os-retention-days', 180));
const guard = (text, where) => {
  for (const [label, s] of [
    ['数据库口令', secret],
    ['SSH 口令', sshSecret],
  ]) {
    if (s.value && String(text).includes(s.value)) {
      throw new Error(`检测到${label}出现在 ${where} —— 已中止，请检查代码是否有泄漏点。`);
    }
  }
  return text;
};

const { ensureHome } = await load('lib/bridge.js');
const { ALL_QUERIES, QUERY_PURPOSE } = await load('lib/queries.js');
const { collect, collectOs } = await load('lib/drivers/index.js');
const { runChecks, LEVELS, LEVEL_LABEL, normalizeAll, buildMeta } = await load('lib/analyze.js');
const { buildReportHtml, renderText } = await load('lib/report.js');

const bar = (t) => console.log(`\n${'='.repeat(72)}\n${t}\n${'='.repeat(72)}`);
const stamp = () => new Date().toISOString().slice(0, 19).replace('T', ' ');

bar(`真机验证：${host}:${port}　账号 ${user}　口令来源 ${secret.source}`);
console.log(`声明权限层：${privs.join('、')}${user.toUpperCase() === 'SYSDBA' ? '' : `　⚠️ 连接账号 ${user} 不是 SYSDBA，部分检查项的结论会受权限影响（读不到的项判「未取到」）`}`);
ensureHome(home);

const t0 = Date.now();
let data;
try {
  data = await collect({ home, driver: 'jdbc', host, port, user, password: secret.value }, ALL_QUERIES);
} catch (e) {
  console.error(`\n采集失败：${e.message}`);
  if (/口令|password|认证|login/i.test(String(e.message))) {
    console.error('（看起来是认证问题：请确认账号口令；本脚本不会重试，避免累加失败登录次数把账号锁掉。）');
  }
  process.exit(1);
}
const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`采集完成：${Object.keys(data).length} 条查询，用时 ${elapsed}s`);

// ---------------------------------------------------------------- 1. 真实列名与错误
console.log('\n--- 1. 每条查询的真实返回（列名 / 行数 / 错误）---');
const findings = { target: `${host}:${port}`, user, generatedAt: stamp(), queries: {}, checks: {} };
for (const q of ALL_QUERIES) {
  const r = data[q.key] ?? { columns: null, rows: [], error: 'NO_RESULT' };
  const cols = Array.isArray(r.columns) ? r.columns.join(', ') : '(无列名)';
  const flag = r.error ? `❌ ${r.error}` : `✅ ${r.rows?.length ?? 0} 行`;
  console.log(`\n[${q.key}] ${QUERY_PURPOSE[q.key] ?? ''}`);
  console.log(`   列名: ${cols}`);
  console.log(`   结果: ${flag}`);
  findings.queries[q.key] = { columns: r.columns ?? null, rowCount: r.rows?.length ?? 0, error: r.error ?? null, purpose: QUERY_PURPOSE[q.key] ?? null };
}

// ---------------------------------------------------------------- 2. 判定
const normalized = normalizeAll(data);
// 主机侧（P2）：配了 --ssh-user + SSH 口令才做；没配就是 null（那 7 项判「不适用」，并说明怎么开）
// ⚠️ 变量名不能叫 `os`：本文件顶部已经 `import os from 'node:os'`（取家目录用）。
const osProbe = collectOs({ driver: 'jdbc', host, port, ssh }, { ssh, dbPort: port, retentionDays: osRetentionDays });
const result = runChecks(data, { privs, complianceLevel: level, os: osProbe });
bar(`2. 判定结果：严重 ${result.counts.crit} / 警告 ${result.counts.warn} / 合规 ${result.counts.ok} / 提示 ${result.counts.info} / 不适用 ${result.counts.na} / 未取到 ${result.counts.unknown}`);
console.log(`等保对照级别：第 ${level} 级（${levelMeta(level).label}）　因级别差异判「不适用」${result.naByLevel} 项`);
console.log(
  `主机侧（OS/SSH）：${
    osProbe === null
      ? '未启用（未给 --ssh-user 与 SSH 口令）'
      : osProbe.state === 'ok'
        ? `已启用 —— ${osProbe.detail}`
        : `已启用但未取到 —— ${osProbe.detail}`
  }`,
);
console.log(
  `形态：${result.shape.cluster}　实例 ${result.shape.instanceName}　库 ${result.shape.dbName}　版本 ${result.shape.version}${
    result.shape.build ? `（${result.shape.build}）` : ''
  }`,
);
console.log(`安全版信号：${result.shape.secure ? result.shape.secureSignals.join('；') : '未检测到'}　职责分离：${result.shape.privMode ?? '未取得'}`);
console.log(
  LEVELS.map((lv) => `${LEVEL_LABEL[lv]} ${result.counts[lv]}`).join('　') + `　（已判定 ${result.assessed} 项；不给出评分）`,
);

console.log('\n--- 严重 / 警告 ---');
for (const r of result.results.filter((x) => x.level === 'crit' || x.level === 'warn')) {
  console.log(`\n[${LEVEL_LABEL[r.level]}] ${r.title}（${r.id}）`);
  console.log(`   ${r.message}`);
  // 多项内容按列表逐条打印（与报告、工具文本输出保持一致）
  for (const it of r.items ?? []) console.log(`     · ${it}`);
  if (r.advice) console.log(`   修复：${r.advice}`);
}

console.log('\n--- 不适用（NA）---');
for (const x of result.results.filter((i) => i.level === 'na')) {
  const tag =
    x.levelApplicability === 'below-level'
      ? `（第 ${x.minLevel} 级起要求 · 属级别差异，按第 ${x.minLevel} 级口径的技术结论仍保留：${x.originalLevel}）`
      : '（产品形态 / 本实例不提供该能力）';
  console.log(`- ${x.id}${tag}：${x.message}`);
}

console.log('\n--- 未取到（UNKNOWN，需补齐）---');
for (const r of result.results.filter((x) => x.level === 'unknown')) console.log(`- ${r.id}：${r.message}`);

for (const r of result.results)
  findings.checks[r.id] = {
    level: r.level,
    title: r.title,
    message: r.message,
    queries: r.queries,
    minLevel: r.minLevel ?? null,
    levelApplicability: r.levelApplicability ?? null,
    originalLevel: r.originalLevel ?? null,
  };

// ---------------------------------------------------------------- 2b. 主机侧事实（P2）
if (osProbe?.state === 'ok' && osProbe.facts) {
  bar('2b. 主机侧事实（OS / SSH）');
  const f = osProbe.facts;
  console.log(`采集：${osProbe.detail}`);
  console.log(`进程：${f.processes.map((p) => `${p.user}(pid ${p.pid}) ${p.cmd}`).join('；') || '(未定位到 dmserver)'}`);
  console.log(`实例配置：${f.primaryProcess?.iniPath ?? '—'}　DM 安装目录：${f.dmHome ?? '—'}　审计目录：${f.auditDir ?? '—'}`);
  for (const s of f.stat) console.log(`  ${String(s.mode).padEnd(5)} ${s.owner}:${s.group}  ${s.path}`);
  console.log(`监听项：${f.listen.map((l) => `${l.addr}:${l.port}`).join('、') || '(无输出)'}`);
  console.log(`sshd：${Object.entries(f.sshd).map(([k, v]) => `${k}=${v}`).join('　') || '(未读到)'}`);
  console.log(`审计文件：${f.auditFiles.length} 个　最旧/最新：${f.auditOldest?.date ?? '—'} / ${f.auditNewest?.date ?? '—'}　保留期要求 ${f.retentionDays} 天`);
  console.log(`明文口令命中：脚本 ${f.plaintextHits.length} 处、历史 ${f.historyHits.length} 处（片段已掩码）`);
  for (const h of [...f.plaintextHits, ...f.historyHits].slice(0, 6)) console.log(`  · ${h.file ?? '~/.bash_history'}${h.lineno ? `:${h.lineno}` : ''} → ${h.snippet}`);
  findings.os = {
    state: osProbe.state,
    detail: guard(osProbe.detail, '主机侧说明'),
    commands: osProbe.commands.map((c) => ({ key: c.key, command: guard(c.command, '主机侧命令'), status: c.status, ok: c.ok })),
    facts: {
      processes: f.processes,
      dmHome: f.dmHome,
      auditDir: f.auditDir,
      dbPort: f.dbPort,
      stat: f.stat,
      listen: f.listen,
      sshd: f.sshd,
      auditFiles: f.auditFiles,
      retention: f.retention,
      plaintextHits: f.plaintextHits,
      historyHits: f.historyHits,
    },
  };
} else if (osProbe) {
  bar('2b. 主机侧事实（OS / SSH）');
  console.log(`未取到：${guard(osProbe.detail, '主机侧说明')}`);
  findings.os = { state: osProbe.state, detail: guard(osProbe.detail, '主机侧说明'), commands: osProbe.commands };
}

// ---------------------------------------------------------------- 3. 待核实清单（自动对账）
bar('3. DESIGN §8 待核实清单 —— 自动对账');
const colsOf = (k) => (data[k]?.columns ?? []).map((c) => String(c).toUpperCase());
const has = (k, c) => colsOf(k).includes(c);
const rowsOf = (k) => data[k]?.rows?.length ?? 0;
const params = new Map();
for (const r of normalized.params?.rows ?? []) params.set(String(r.PARA_NAME ?? '').toUpperCase(), r);
const pv = (n) => (params.has(n.toUpperCase()) ? String(params.get(n.toUpperCase()).PARA_VALUE ?? '') : '(本版本无此参数)');

const checks = [
  ['DBA_USERS 是否有 ALLOW_IP / NOT_ALLOW_IP', has('userAccess', 'ALLOW_IP') ? '✅ 存在' : '❌ 不存在（保持 unknown 实现）'],
  ['DBA_USERS 是否有 ALLOW_DATETIME', has('userAccess', 'ALLOW_DATETIME') ? '✅ 存在' : '❌ 不存在（保持 unknown 实现）'],
  ['DBA_USERS 是否有 AUTHENTICATION_TYPE', has('users', 'AUTHENTICATION_TYPE') ? '✅ 存在' : '❌ 不存在'],
  ['DBA_USERS 是否有 LOCK_DATE / EXPIRY_DATE', has('users', 'LOCK_DATE') && has('users', 'EXPIRY_DATE') ? '✅ 都有' : '⚠️ 缺一个'],
  ['SYSUSERS 是否有 SESSION_PER_USER', has('pwdPolicy', 'SESSION_PER_USER') ? '✅ 存在' : '❌ 不存在（资源限制项保持 unknown）'],
  ['SYSUSERS 是否有 CPU_PER_SESSION', has('pwdPolicy', 'CPU_PER_SESSION') ? '✅ 存在' : '❌ 不存在'],
  ['SYSUSERS 是否有 MEM_SPACE', has('pwdPolicy', 'MEM_SPACE') ? '✅ 存在' : '❌ 不存在'],
  ['SYSUSERS 是否有口令重用列', colsOf('pwdPolicy').some((c) => /REUSE|HISTORY/.test(c)) ? '✅ 存在' : '❌ 不存在'],
  ['DBA_TAB_PRIVS 列名可用', data.tabPrivs?.error ? `❌ ${data.tabPrivs.error}` : `✅ ${colsOf('tabPrivs').join('/')}`],
  ['DBA_PROFILES 是否可用', data.profiles?.error ? `❌ ${data.profiles.error}` : `✅ ${rowsOf('profiles')} 行`],
  ['审计记录视图可见性', data.auditRecords?.error ? `❌ ${data.auditRecords.error}` : `✅ 可读，N=${normalized.auditRecords?.rows?.[0]?.N ?? '?'}`],
  ['MAC 字典对象', data.macObjs?.error ? `❌ ${data.macObjs.error}` : `${rowsOf('macObjs')} 个`],
  ['存储加密相关对象', data.encObjs?.error ? `❌ ${data.encObjs.error}` : `${rowsOf('encObjs')} 个`],
  ['PRIV_FLAG 是否存在（安全版信号）', params.has('PRIV_FLAG') ? `✅ 存在，值=${pv('PRIV_FLAG')}` : '❌ 不存在（普通版）'],
  ['ENABLE_AUDIT', `值=${pv('ENABLE_AUDIT')}`],
  ['AUDIT_FILE_FULL_MODE', `值=${pv('AUDIT_FILE_FULL_MODE')}`],
  ['PWD_POLICY / PWD_MIN_LEN', `值=${pv('PWD_POLICY')} / ${pv('PWD_MIN_LEN')}`],
  ['ENABLE_ENCRYPT（通信加密）', `值=${pv('ENABLE_ENCRYPT')}`],
  ['ENABLE_REMOTE_OSAUTH', `值=${pv('ENABLE_REMOTE_OSAUTH')}`],
  ['GRANT_SCHEMA', `值=${pv('GRANT_SCHEMA')}`],
  ['作业子系统 SYSJOB.SYSJOBS', data.jobs?.error ? `❌ ${data.jobs.error}` : `✅ ${rowsOf('jobs')} 个作业`],
  ['版本（补丁基线的起点）', `${result.shape.version ?? '?'}${result.shape.build ? ` / ${result.shape.build}` : ''}`],
  // 主机侧（P2）：配了 SSH 才有内容
  ['主机侧进程账号', osProbe?.facts?.primaryProcess ? `${osProbe.facts.primaryProcess.user}（pid ${osProbe.facts.primaryProcess.pid}）` : osProbe ? `未取到：${osProbe.detail}` : '未启用 SSH'],
  ['主机侧 DM 安装目录 / 审计目录', osProbe?.facts ? `${osProbe.facts.dmHome ?? '—'} / ${osProbe.facts.auditDir ?? '—'}` : '未启用 SSH'],
  ['主机侧审计文件保留', osProbe?.facts?.retention ? `${osProbe.facts.retention.detail}（要求 ${osProbe.facts.retentionDays} 天，判定 ${osProbe.facts.retention.state}）` : '未启用 SSH'],
  ['主机侧明文口令痕迹', osProbe?.facts ? `脚本 ${osProbe.facts.plaintextHits.length} 处 / 历史 ${osProbe.facts.historyHits.length} 处（已掩码）` : '未启用 SSH'],
];
for (const [k, v] of checks) console.log(`- ${k.padEnd(42, '·')} ${v}`);
findings.pending = Object.fromEntries(checks);

// 参数快照（只留安全相关的）
findings.params = Object.fromEntries(
  [...params.entries()].filter(([k]) => /AUDIT|PWD|ENCRYPT|OSAUTH|PRIV_FLAG|GRANT_SCHEMA|AUTH|SSL|MAC|SESSIONS/.test(k)),
);

// ---------------------------------------------------------------- 4. 报告
bar('4. 落盘');
fs.mkdirSync(outDir, { recursive: true });
const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '').replace(/-/g, '');
const base = `${host}_${port}`;
// meta 统一由插件导出（buildMeta）构造 —— 手拼会漏字段（曾因此把「版本类型/授权」显示成未取到）
const meta = buildMeta(result.shape, {
  account: user,
  privSource: `脚本声明权限层：${privs.join('、') || '无'}`,
  target: `${host}:${port}`,
  osAccess:
    osProbe === null
      ? '未启用（纯 JDBC 只读；未提供 --ssh-user 与 SSH 口令）'
      : osProbe.state === 'ok'
        ? `已启用（${osProbe.detail}）`
        : `已启用但未取到：${osProbe.detail}`,
  versionEvidence: { sql: normalized.buildType?.sqlUsed ?? null, row: normalized.buildType?.rows?.[0] ?? null },
});
const htmlPath = path.join(outDir, `dm-security-${base}-${ts}.html`);
const jsonPath = path.join(outDir, `dm-security-${base}-${ts}.findings.json`);
const html = buildReportHtml({
  meta,
  result,
  snapshots: normalized,
  generatedAt: stamp(),
  driver: 'jdbc',
  disclaimer:
    '本报告由只读评估生成：插件未执行任何变更，未试默认口令，未采集口令散列。\n\n' +
    '「不适用」与「不合规」是两个不同的结论；「未取到」既不代表合规也不代表不合规。',
});
fs.writeFileSync(htmlPath, guard(html, 'HTML 报告'), 'utf8');
fs.writeFileSync(jsonPath, guard(JSON.stringify(findings, null, 2), 'findings JSON'), 'utf8');
console.log(`HTML 报告：${htmlPath}`);
console.log(`findings：${jsonPath}`);

bar('5. 会话文本结论（与工具 assess 动作同源）');
console.log(guard(renderText(result, meta), '文本结论'));
