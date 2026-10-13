/**
 * 达梦数据库安全评估 —— DSH 插件入口。
 *
 * 边界（写死在实现里，不是配置项）：
 *   · 只注册**只读**查询；桥只放行 SELECT / WITH，其余一律拒绝；
 *   · **不提供**任何「为验证而变更」的能力：不试默认口令、不建审计策略试探、不改资源限制；
 *   · 不采集 `DBA_USERS.PASSWORD`（分析层的 redact 会兜底丢弃）。
 *
 * 判定口径见 DESIGN.md §2：六态结论（严重/警告/提示/合规/不适用/未取到），
 * 其中「不适用」与「未取到」不进结论统计（本工具不评分）。
 */

import { defineTool } from '@deepseek-ai/dsh-tools';
import fs from 'node:fs';
import path from 'node:path';

import { defaultHome, ensureHome } from './bridge.js';
import { ALL_QUERIES } from './queries.js';
import { collect, collectOs } from './drivers/index.js';
import { runChecks, DEFAULT_THRESHOLDS, normalizeAll, buildMeta } from './analyze.js';
import { judgeNodeConsistency, renderConsistencyText, describeCoverage } from './dsc.js';
import { DEFAULT_OS_RETENTION_DAYS } from './ossh.js';
import { buildReportHtml, renderText } from './report.js';
import { CHECKS, DOMAINS } from './checks.js';
import {
  COMPLIANCE_LEVELS,
  DEFAULT_COMPLIANCE_LEVEL,
  normalizeLevel,
  levelMeta,
  standardName,
  parseControl,
  minLevelOf,
} from './compliance.js';

const TOOL_NAME = 'dm_security_assess';

/** 需要 tools 服务；没有它本插件不加载。 */
const inject = ['tools'];

/**
 * 参数 spec 用的是 DSH 自定义 DSL（defineTool 会编译成 JSON Schema）：
 * 参数对象是隐式开放根，直接写「名字 → spec」，必填靠 `required: true`。
 */
const PARAMETERS = {
  action: {
    type: 'string',
    enum: ['assess', 'report', 'list'],
    required: true,
    description:
      'assess=只读评估并在会话里给出文本结论；report=评估并落盘一份 HTML 报告（对齐 dm8-inspect 的交付形态）；' +
      'list=只列出检查项目录（**不连库**，用于确认本次评估的范围与判定口径）。',
  },
  driver: {
    type: 'string',
    enum: ['jdbc', 'demo'],
    description:
      'jdbc=连真实达梦库（默认）；demo=用内置样例数据跑通流程（**不连库**），用于无环境时验证报告与判定分支。',
  },
  level: {
    type: 'integer',
    description:
      `等保 2.0 对照级别：${COMPLIANCE_LEVELS.join(' / ')}（第二 / 三 / 四级），默认 ${DEFAULT_COMPLIANCE_LEVEL}。` +
      '级别决定两件事：①条款编号（二级 7.1.4.x / 三级 8.1.4.x / 四级 9.1.4.x）；②要求范围 —— 高等级专属条款在当前级别下判**「不适用」**而不是「不符合」' +
      '（例如二级对照时，双因素鉴别、安全标记、审计进程保护、管理终端限制、漏洞修补等项会判不适用），但每项的技术结论、证据与整改建议仍会保留，升级定级时可直接复用。' +
      '为什么默认三级：三级在本插件用到的范围内基本覆盖二级，按三级做不会漏检，二级客户只是多出几条按级别降级的「不适用」。',
  },
  outDir: {
    type: 'string',
    description: 'report 用：HTML 报告输出目录，默认 <插件工作目录>/dm-security-reports。可用 ~ 开头。',
  },
  targets: {
    type: 'string',
    description:
      'DMDSC / 数据守护多节点：各节点的 host:port，逗号/空格/换行分隔（端口省略则 5236）。' +
      '给了之后会**逐节点**采集并各出一份结论；不给则只评估 host/port 指向的这一个实例。' +
      '为什么必须由你给：达梦的 `V$DSC_EP_INFO` 不含地址列，插件无法自动发现对端节点。',
  },
  pwdPolicyMin: { type: 'integer', description: `PWD_POLICY 位掩码基线，默认 ${DEFAULT_THRESHOLDS.pwdPolicyMin}（禁同名+长度≥9+大写+数字+标点）` },
  pwdMinLen: { type: 'integer', description: `口令最小长度基线，默认 ${DEFAULT_THRESHOLDS.pwdMinLen}` },
  pwdLifeMaxDays: { type: 'integer', description: `口令有效期上限（天），默认 ${DEFAULT_THRESHOLDS.pwdLifeMaxDays}` },
  failedLoginMax: { type: 'integer', description: `登录失败锁定次数上限，默认 ${DEFAULT_THRESHOLDS.failedLoginMax}` },
  maxSessionsWarnPct: { type: 'integer', description: `会话上限使用率告警线（%），默认 ${DEFAULT_THRESHOLDS.maxSessionsWarnPct}` },
  sessionShareWarn: { type: 'integer', description: `单一来源会话占比告警线（%），默认 ${DEFAULT_THRESHOLDS.sessionShareWarn}` },
  host: { type: 'string', description: '数据库服务器 IP 或主机名（也可只填在调用卡片里）' },
  port: { type: 'integer', description: '数据库端口，默认 5236（DMDSC 常见 7236 / 7237）' },
  user: { type: 'string', description: '数据库账号，默认 SYSDBA（本插件 P0 全部检查项都只需 SYSDBA 只读权限）' },
  privs: {
    type: 'string',
    description:
      '声明连接账号实际具备的权限层，逗号分隔（如 `SYSDBA`）。**默认自动判定**：账号是 SYSDBA，或该账号持有 DBA 角色，' +
      '即按 SYSDBA 处理；否则所有需要 SYSDBA 的检查项判「未取到」而**不会**假装有权限。一般不需要手动指定。',
  },
  password: {
    type: 'string',
    description:
      '数据库口令：**每次调用时在卡片里填本次要用的口令**（常规用法，不保存、不落盘）。插件只把它用于本次运行 —— 不写入任何配置文件、不写进报告；' +
      '唯一会留下记录的地方是宿主的会话日志（本插件无法避免）。介意这一点时，可改用凭据库：在插件配置里填 `credentialRef`，之后调用就不必再填口令。',
  },
  sshUser: {
    type: 'string',
    description:
      'OS/SSH 侧（主机侧 7 项检查）用：数据库主机的 SSH 账号，通常 `dmdba`（要读 `/etc/ssh/sshd_config` 时用 root）。' +
      '**不给就不做任何主机侧检查** —— 那 7 项判「不适用」并说明原因，插件保持纯 JDBC 只读。',
  },
  sshPassword: {
    type: 'string',
    description:
      'OS/SSH 侧的 SSH 口令（与 `password` 同样：每次调用时填、不保存）。**与 `sshUser` 同时给出才启用主机侧采集**；' +
      '插件在主机上只执行白名单里的只读命令（ps / stat / ss / grep / find），没有任何写操作、不改任何配置。',
  },
  sshPort: { type: 'integer', description: 'SSH 端口，默认 22' },
  sshHost: {
    type: 'string',
    description:
      'SSH 目标主机，逗号分隔且**与 targets 同序**（DMDSC 逐节点）；默认直接用每个数据库目标自己的 host —— 库与 OS 在同一台机器时不用填。',
  },
  sshHostKey: {
    type: 'string',
    description:
      '目标主机密钥指纹（形如 `ssh-ed25519 255 SHA256:…`）。plink 在 `-batch` 模式下要求主机密钥已知，不给会在主机密钥确认处中止 —— 也可以先手工接受一次。',
  },
  plinkPath: { type: 'string', description: 'plink 可执行文件路径，默认从 PATH 找 `plink`（Windows 上非交互传 SSH 口令只能靠 plink）' },
  osRetentionDays: {
    type: 'integer',
    description: '审计文件保留期要求（天），默认 180：主机侧检查看审计目录里最旧的文件够不够这个跨度。**这是业务决策**，按你单位的留痕要求改。',
  },
};

/** 输出 schema：显式 object + additionalProperties: false，必填逐项标 required。 */
const OUTPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    action: { type: 'string', required: true, description: '本次执行的动作：assess / report / list' },
    // ★ 2026-10-12 按用户要求**取消评分**：输出里不再有 score / grade。
    //   理由见 DESIGN §2.2：加权评分会把「硬性不符合」与「加固建议」压成一个数字，
    //   读者容易只盯分数不看具体项；等保测评本身也是逐条判定而非打分。
    //   改由 text 里的「结论分布（六态计数）+ 逐项结论」承载结论。
    //   ⚠️ 这次改动改了输出契约，**宿主需重新加载插件**才会生效；在旧模块下调用会报
    //   「缺少必填字段 score」——那是预期现象，不是新缺陷。
    text: { type: 'string', required: true, description: '渲染后的完整文本结论（含采集账号、结论分布与逐项结论）' },
    reportPath: { type: 'string', description: 'report 动作落盘的主报告绝对路径' },
    reportPaths: { type: 'string', description: 'report 动作落盘的全部报告路径（多节点时以换行分隔）' },
  },
};

const DISCLAIMER = [
  '本报告为**只读评估**：插件不执行任何变更，不试默认口令、不建审计策略、不改资源限制。',
  '「不适用」与「不合规」是两个不同的结论：普通版（标准版/企业版）不提供强制访问控制与四权分立，属产品形态，不计为缺陷。',
  '「未取到」表示数据没拿到（权限不足、字典不存在或需要 OS 侧数据），**既不代表合规也不代表不合规**，请按报告第四节的补齐办法人工核对。',
  '等保控制点编号随对照级别变化（`level` = 2 / 3 / 4 → 7.1.4.x / 8.1.4.x / 9.1.4.x），编号与要求摘要均为工作基线，最终判定请以测评机构的结论为准。',
  '主机侧检查（`os` 域 7 项）仅在配置了 `sshUser` / `sshPassword` 时执行：插件在主机上只跑 `lib/ossh.js` 白名单里的只读命令（ps / stat / ss / grep / find），没有写操作、不改任何配置；明文口令扫描的命中片段在采集层就已掩码。',
  '评估结论基于采集时刻的配置快照；参数与权限可能随后变更，建议纳入常态化巡检。',
].join('\n\n');

/**
 * 口令解析：调用参数（卡片里现填，本次运行）> 凭据库 > 插件配置。
 *
 * 常规用法是**每次在调用卡片里填**（用户偏好：不保存、不落盘、不必配凭据库）；
 * 凭据库只是「不想让口令进会话日志」时的可选替代，不是必需品。
 */
async function resolvePassword(ctx, args, config) {
  if (typeof args.password === 'string' && args.password !== '') {
    return { value: args.password, source: '调用参数（本次运行，插件未落盘）' };
  }
  if (typeof config.password === 'string' && config.password !== '') {
    return { value: config.password, source: '插件配置（口令已写在配置文件里）' };
  }
  const ref = config.credentialRef;
  if (!ref) return { value: null, source: '未提供（调用卡片里未填 password）' };
  const credentials = typeof ctx.get === 'function' ? ctx.get('credentials') : undefined;
  if (!credentials || typeof credentials.resolve !== 'function') return { value: null, source: '凭据服务不可用' };
  try {
    const got = await credentials.resolve(ref);
    const v = typeof got === 'string' ? got : (got?.secret ?? got?.value ?? null);
    return { value: v ?? null, source: v ? `凭据库(${ref})` : `凭据库(${ref}) 中无值` };
  } catch (e) {
    return { value: null, source: `凭据库读取失败: ${e.message}` };
  }
}

/** 目标解析：targets 优先，否则用 host/port。 */
function parseTargets(text, fallback) {
  const raw = String(text ?? '').trim();
  if (!raw) return [fallback];
  const out = [];
  for (const piece of raw.split(/[\s,;]+/).filter(Boolean)) {
    const [h, p] = piece.split(':');
    if (!h) continue;
    out.push({ host: h, port: Number(p || fallback.port || 5236), label: `${h}:${p || fallback.port || 5236}` });
  }
  return out.length ? out : [fallback];
}

function expandHome(p) {
  const s = String(p ?? '').trim();
  if (!s) return s;
  if (s === '~') return process.env.HOME || process.env.USERPROFILE || s;
  if (s.startsWith('~/') || s.startsWith('~\\')) {
    const base = process.env.HOME || process.env.USERPROFILE || '';
    return path.join(base, s.slice(2));
  }
  return s;
}

function stamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

const safeName = (s) => String(s ?? 'DM').replace(/[^\w.\u4e00-\u9fa5-]+/g, '_').slice(0, 40);

/**
 * 检查项目录（list 动作，不连库）。
 * 条款编号与「本级是否适用」都按对照级别给出 —— 目录本身就该回答「这一级要查哪些」。
 */
function renderCatalog(level = DEFAULT_COMPLIANCE_LEVEL) {
  const lv = normalizeLevel(level);
  const m = levelMeta(lv);
  const lines = [
    `达梦安全评估检查项目录：共 ${CHECKS.length} 项，分 ${DOMAINS.length} 个域。`,
    `等保对照级别：第 ${lv} 级（${m.label}）· ${standardName(lv)}。标「第 N 级起要求」的项在本级判「不适用」（级别差异，不是安全缺陷）。`,
    '',
  ];
  for (const d of DOMAINS) {
    const items = CHECKS.filter((x) => x.domain === d.key);
    lines.push(`【${d.order}. ${d.title}】${items.length} 项`);
    for (const it of items) {
      const pre = [
        it.edition === 'secure' ? '仅安全版' : null,
        // 主机侧检查（priv === null）走 SSH，不看数据库账号 —— 报成「需 null」会让人以为要权限
        it.priv === null ? '需 SSH' : it.priv !== 'SYSDBA' ? `需 ${it.priv}` : '需 SYSDBA',
      ]
        .filter(Boolean)
        .join(' / ');
      const ids = it.compliance ?? [];
      const ctl = ids.map((c) => parseControl(c, lv)).filter(Boolean).map((p) => p.id);
      const minL = minLevelOf(ids);
      const ctlText = ctl.length ? ctl.join(' ') : '（加固项）';
      const flag = minL > lv ? `　← 第 ${minL} 级起要求，本级不适用` : '';
      lines.push(`  ${it.id}  ${it.title}　[最重结论 ${it.level}｜${pre}｜等保 ${ctlText}]${flag}`);
    }
    lines.push('');
  }
  lines.push(
    '说明：所有检查项均为只读查询；「不适用」与「未取到」不进结论统计（本工具不评分）。等保条款编号随对照级别变化，口径详见 DESIGN.md §2.5。',
  );
  return lines.join('\n');
}

/**
 * 判定「连接账号实际具备哪个权限层」。
 *
 * ★ 为什么必须有：检查项的 `priv` 是「拿数据所需的最小权限」。如果连接账号不是 SYSDBA
 *   却一律按 SYSDBA 判定，报告会**假装拿到了权限**（真机验证时用 APPUSER 连接就是这样）。
 *   判定顺序：显式参数 → 账号就是 SYSDBA → 账号持有 DBA 角色（等效）→ 否则为空集
 *   （此时所有需要 SYSDBA 的项判「未取到」，并说明原因）。
 */
function detectPrivs(user, data, explicit) {
  if (explicit) {
    const list = String(explicit).split(',').map((s) => s.trim()).filter(Boolean);
    if (list.length) return { list, source: '调用参数指定' };
  }
  const u = String(user ?? '').trim().toUpperCase();
  if (u === 'SYSDBA') return { list: ['SYSDBA'], source: '连接账号即 SYSDBA' };
  const hasDba = (data?.rolePrivs?.rows ?? []).some(
    (r) => String(r.GRANTEE ?? '').trim().toUpperCase() === u && String(r.GRANTED_ROLE ?? '').trim().toUpperCase() === 'DBA',
  );
  if (hasDba) return { list: ['SYSDBA'], source: `连接账号 ${u} 持有 DBA 角色 → 按 SYSDBA 等效判定` };
  return { list: [], source: `连接账号 ${u} 既不是 SYSDBA、也未见 DBA 角色 → 需要 SYSDBA 的检查项将判「未取到」` };
}

/**
 * SSH 配置解析（P2）。
 *
 * 纪律（与 DESIGN §1.2 的「只读」边界一致）：
 *   · `sshUser` 与 `sshPassword` **缺一即视为「没配 OS 访问」** —— 不做主机侧采集，
 *     那 7 项检查判「不适用」并说明怎么开，插件退回纯 JDBC 只读；
 *   · `sshHost` / `sshHostKey` / `sshPort` 可给逗号列表且**与 targets 同序**（DMDSC 逐节点）；
 *     ⚠️ 主机密钥**必须逐节点**：实测两节点指纹不同（`SHA256:Zk6v3…` / `SHA256:PcGIK…`），
 *     只给一个值会让第二个节点在 plink 的主机密钥确认处中止。只给一个值时按「所有节点相同」处理。
 *   · 任何一项没配齐都不报错、不猜 —— 猜一个主机名去连是这一层最不该做的事。
 */
function sshConfigOf({ args, cfg, targets }) {
  const user = args.sshUser ?? cfg.sshUser;
  const password = args.sshPassword ?? cfg.sshPassword;
  if (!user || !password) return null;
  /** 逗号/空格列表 → 按节点数对齐；只有一个值时认为所有节点相同。 */
  const align = (v, def) => {
    const list = String(v ?? '').split(/[\s,;]+/).filter(Boolean);
    if (!list.length) return targets.map(() => def);
    return targets.map((_, i) => list[i] ?? list[0]);
  };
  const hosts = align(args.sshHost ?? cfg.sshHost, null);
  const keys = align(args.sshHostKey ?? cfg.sshHostKey, null);
  const ports = align(args.sshPort ?? cfg.sshPort, 22);
  const nodes = targets.map((t, i) => ({
    label: t.label,
    host: hosts[i] ?? t.host,
    port: Number(ports[i] ?? 22),
    user,
    password,
    hostKey: keys[i] ?? null,
    plinkPath: args.plinkPath ?? cfg.plinkPath ?? 'plink',
  }));
  return { nodes, hostCount: hosts.filter(Boolean).length };
}

/** 单节点：采集 → 判定 → 结论对象。 */
async function assessTarget(conn, args, opts) {
  const raw = await collect(conn, ALL_QUERIES);
  const data = normalizeAll(raw);
  const privsInfo = detectPrivs(conn.user, data, args.privs);
  // 主机侧是**另一条通道**：走 SSH 而不是 JDBC。没配就返回 null → 那 7 项判「不适用」并说明原因。
  const os = collectOs(conn, { ssh: conn.ssh ?? null, dbPort: conn.port, retentionDays: opts.osRetentionDays });
  const result = runChecks(data, { ...opts, privs: privsInfo.list, os });
  const meta = buildMeta(result.shape, {
    account: conn.user,
    privSource: privsInfo.source,
    target: conn.label ?? `${conn.host}:${conn.port}`,
    /** OS 访问状态：报告「评估概况」里要如实写出「本次有没有查主机侧」 */
    osAccess:
      os === null
        ? '未启用（纯 JDBC 只读；未提供 sshUser / sshPassword）'
        : os.state === 'ok'
          ? `已启用（${os.detail}）`
          : `已启用但未取到：${os.detail}`,
    osCommands: os?.commands ?? null,
    // 版本号的**取值证据**（原始 SQL + 原始行），报告里可展开复核
    versionEvidence: { sql: data.buildType?.sqlUsed ?? null, row: data.buildType?.rows?.[0] ?? null },
  });
  return { data, result, meta };
}

function apply(ctx, config = {}) {
  const getConfig = () => ({
    home: config.home || defaultHome(),
    driver: config.driver,
    host: config.host,
    port: config.port ?? 5236,
    user: config.user ?? 'SYSDBA',
    password: config.password,
    credentialRef: config.credentialRef,
    driverJar: config.driverJar,
    javaHome: config.javaHome,
    timeoutSec: config.timeoutSec ?? 180,
    outDir: config.outDir,
    sshUser: config.sshUser,
    sshPassword: config.sshPassword,
    sshPort: config.sshPort,
    sshHost: config.sshHost,
    sshHostKey: config.sshHostKey,
    plinkPath: config.plinkPath,
    osRetentionDays: config.osRetentionDays,
  });

  const tool = defineTool({
    name: TOOL_NAME,
    description: [
      '达梦（DM8）数据库**安全评估**：按 ',
      `${DOMAINS.length} 个域、`,
      `${CHECKS.length} 项只读检查，逐项给出 严重/警告/提示/合规/不适用/未取到 六态结论、证据 SQL、修复建议，`,
      '并映射到等保 2.0 控制点（`level` 可选 2 / 3 / 4，默认第三级）。**不评分**：结论以逐项六态判定为准。',
      '**只读**：不试默认口令、不建审计策略、不改任何配置，也不采集口令散列。',
      '特别注意：普通版不提供强制访问控制与四权分立，这些项会判「不适用」而不是「不合规」。',
    ].join(''),
    timeoutMs: 600000,
    isConcurrencySafe: () => true,
    parameters: PARAMETERS,
    output: {
      schema: OUTPUT_SCHEMA,
      render: (_args, v) => [{ type: 'text', text: String(v?.text ?? '') }],
    },
    async execute(args) {
      const cfg = getConfig();
      const home = ensureHome(cfg.home);
      const driver = String(args.driver ?? cfg.driver ?? 'jdbc').toLowerCase();

      // 等保对照级别：非法值直接说清楚，不要静默退回默认 —— 静默退回会让报告口径与调用者预期不符
      const level = args.level === undefined || args.level === null || args.level === '' ? DEFAULT_COMPLIANCE_LEVEL : Number(args.level);
      if (!COMPLIANCE_LEVELS.includes(level)) {
        return {
          action: args.action,
          text: `level 只支持 ${COMPLIANCE_LEVELS.join(' / ')}（等保第二 / 三 / 四级对照），收到 ${JSON.stringify(args.level)}。`,
        };
      }

      if (args.action === 'list') {
        return { action: 'list', text: renderCatalog(level) };
      }

      const thresholds = {};
      for (const k of Object.keys(DEFAULT_THRESHOLDS)) {
        if (args[k] !== undefined && args[k] !== null) thresholds[k] = Number(args[k]);
      }
      // 主机侧保留期是业务决策：单独解析（不进 DEFAULT_THRESHOLDS，因为它只在 OS 侧用到）
      const osRetentionDays = Number(args.osRetentionDays ?? cfg.osRetentionDays ?? DEFAULT_OS_RETENTION_DAYS);
      const opts = { thresholds, complianceLevel: level, osRetentionDays };

      // demo 不需要口令，也不碰网络
      let password = null;
      let pwSource = '演示数据';
      if (driver !== 'demo') {
        const got = await resolvePassword(ctx, args, cfg);
        password = got.value;
        pwSource = got.source;
        if (!password) {
          return {
            action: args.action,
            text:
              `未取得数据库口令（来源：${pwSource}）。\n` +
              '用法：在调用卡片里填 `password`（只用于本次运行，不写配置、不落盘；口令会出现在宿主会话日志里）。\n' +
              '介意口令进会话日志时，可在插件配置里填 `credentialRef` 改用凭据库。\n' +
              '只想先看报告形态与判定分支，可用 `driver: "demo"`（内置样例数据，不连库）。',
          };
        }
      }

      const targets = parseTargets(args.targets, {
        host: args.host ?? cfg.host ?? '127.0.0.1',
        port: Number(args.port ?? cfg.port),
        label: `${args.host ?? cfg.host ?? '127.0.0.1'}:${Number(args.port ?? cfg.port)}`,
      });

      // 主机侧（P2）：demo 走内置样例；jdbc 需要 sshUser + sshPassword 齐备，否则为 null（判「不适用」）
      const ssh = driver === 'demo' ? null : sshConfigOf({ args, cfg, targets });

      const perNode = [];
      const failed = [];
      for (const t of targets) {
        const conn = {
          home,
          driver,
          host: t.host,
          port: t.port,
          label: t.label,
          user: args.user ?? cfg.user,
          password,
          driverJar: cfg.driverJar,
          javaHome: cfg.javaHome,
          timeoutSec: cfg.timeoutSec,
          /** 该节点对应的 SSH 目标（同序对齐；没配就是 null） */
          ssh: ssh?.nodes.find((n) => n.label === t.label) ?? null,
        };
        try {
          const r = await assessTarget(conn, args, opts);
          // label 与 shape 都要带上：一致性核对靠这两个字段识别节点、比对版本事实
          perNode.push({ label: t.label, shape: r.result.shape, ...r });
        } catch (e) {
          failed.push({ label: t.label, error: String(e?.message ?? e) });
        }
      }

      if (perNode.length === 0) {
        return {
          action: args.action,
          text: '所有目标节点均无法评估：\n' + failed.map((f) => `- ${f.label}：${f.error}`).join('\n'),
        };
      }

      // ---- 多节点：覆盖度说明 + **节点间安全配置一致性核对** ----
      // DSC 每个节点有各自的 dm.ini（V$DM_INI 按节点返回），「某节点少一道控制」这类漂移
      // 只有逐节点比对才发现得了；单节点时两者为空。
      const consistency = perNode.length > 1 ? judgeNodeConsistency(perNode) : null;
      const coverage =
        perNode.length > 1
          ? describeCoverage({
              dscNodes: perNode[0].result.shape.dscNodes,
              targets,
              connected: perNode.map((n) => n.meta.target),
              failedCount: failed.length,
            })
          : '';

      // ---- assess：文本结论 ----
      if (args.action === 'assess') {
        const blocks = perNode.map((n) => renderText(n.result, n.meta));
        const head =
          perNode.length > 1
            ? `本轮评估了 ${perNode.length} 个节点${failed.length ? `（${failed.length} 个节点连接失败）` : ''}。\n${coverage}\n\n`
            : '';
        const tail = failed.length ? `\n\n未能评估的节点：\n${failed.map((f) => `- ${f.label}：${f.error}`).join('\n')}` : '';
        return {
          action: 'assess',
          text: head + blocks.join('\n\n────────\n\n') + (consistency ? renderConsistencyText(consistency) : '') + tail,
        };
      }

      // ---- report：HTML 落盘 ----
      const outDir = expandHome(args.outDir ?? cfg.outDir ?? path.join(home, 'dm-security-reports'));
      fs.mkdirSync(outDir, { recursive: true });
      const ts = stamp();
      const written = [];
      for (const n of perNode) {
        const base = safeName(n.meta.dbName || n.meta.instanceName || n.meta.target);
        const suffix = perNode.length > 1 ? `-${safeName(n.meta.target)}` : '';
        // 文件名带上对照级别：同一套库的不同级别报告放在一起时，光看时间戳分不出哪份是二级的
        const file = path.join(outDir, `dm-security-${base}${suffix}-L${level}-${ts}.html`);
        const html = buildReportHtml({
          meta: n.meta,
          result: n.result,
          snapshots: n.data,
          generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
          disclaimer: DISCLAIMER,
          driver,
          nodeConsistency: consistency,
        });
        fs.writeFileSync(file, html, 'utf8');
        written.push(file);
      }
      const summary =
        `已生成 ${written.length} 份 HTML 安全评估报告：\n` +
        written.map((f, i) => `- ${perNode[i].meta.target}：${f}`).join('\n') +
        (failed.length ? `\n\n未能评估的节点：\n${failed.map((f) => `- ${f.label}：${f.error}`).join('\n')}` : '') +
        (coverage ? `\n\n${coverage}` : '') +
        (consistency ? `\n${renderConsistencyText(consistency)}` : '') +
        '\n\n' +
        renderText(perNode[0].result, perNode[0].meta);
      return {
        action: 'report',
        text: summary,
        reportPath: written[0],
        reportPaths: written.join('\n'),
      };
    },
  });

  ctx.tools.register(tool);
}

const name = 'dm-security-assess';

export { apply, inject, name, CHECKS, DOMAINS };
