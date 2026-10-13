/**
 * 报告渲染：HTML（交付物）+ 文本（DSH 工具返回值）。
 *
 * 呈现原则（2026-10-12 定）：
 *   1. **不出评分**。只给结论分布（六态计数）与逐项结论 —— 加权分数会把「硬性不符合」
 *      与「加固建议」压成一个数字；等保测评本身也是逐条判定。
 *   2. **多项内容一律走列表**（`items`），`message` 只留一句结论（见 DESIGN §2.4）。
 *   3. **等保对照要能看到「要求原文」，而不只是条款号**（见 compliance.js 的摘要说明）。
 *   4. **版面按正式报告做**：封面信息带 → 结论看板 → 编号章节 → 附录；A4 可直接打印成文。
 *
 * HTML 是**零外部依赖**的单文件：不引 CDN、不引字体、不引脚本，拷到任何机器双击可看。
 */

import { LEVEL_LABEL, LEVEL_ORDER, topActions } from './analyze.js';
import { DOMAINS } from './checks.js';
import { QUERY_PURPOSE } from './queries.js';
import {
  parseControl,
  levelMeta,
  normalizeLevel,
  levelBasis,
  standardName,
  DEFAULT_COMPLIANCE_LEVEL,
} from './compliance.js';
import { conformityCounts, CONFORMITY_LABEL, CONFORMITY_ORDER } from './analyze.js';
import { renderConsistencyHtml } from './dsc.js';

export const TOOL_ID = 'dsh-plugin-dm-security v0.1.0';

export function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const inline = (t) =>
  esc(t)
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/`([^`]+)`/g, '<code>$1</code>');

/** 极简 Markdown → HTML：段落 + `**粗体**` + `` `行内代码` ``。 */
export function mdToHtml(md) {
  return String(md ?? '')
    .split(/\n{2,}/)
    .map((p) => `<p>${inline(p).replace(/\n/g, '<br>')}</p>`)
    .join('\n');
}

/** 枚举条目 → 列表。约定：一处列举 ≥3 个同类对象就走这里，别塞进句子。 */
function listBlock(items) {
  if (!items?.length) return '';
  return `<ul class="items">${items.map((t) => `<li>${inline(t)}</li>`).join('')}</ul>`;
}

/** 证据表：列名取各行键的并集（各检查项的证据列不一样）。 */
function evidenceTable(rows) {
  if (!rows?.length) return '';
  const keys = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const head = keys.map((k) => `<th>${esc(k)}</th>`).join('');
  const body = rows
    .slice(0, 40)
    .map((r) => `<tr>${keys.map((k) => `<td>${esc(r[k] ?? '—')}</td>`).join('')}</tr>`)
    .join('\n');
  const more = rows.length > 40 ? `<div class="note">证据仅展示前 40 行，共 ${rows.length} 行。</div>` : '';
  return `<div class="ev-wrap"><table class="ev"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${more}`;
}

/**
 * 等保控制点标签：`8.1.4.2(d) 访问控制 · 授予管理用户所需的最小权限，实现管理用户的权限分离`。
 * 编号按**当前对照级别**给出（二级 7.1.4.x / 四级 9.1.4.x），并要求摘要在该级别下也成立。
 */
function controlLabels(list, level = DEFAULT_COMPLIANCE_LEVEL) {
  const out = [];
  for (const id of list ?? []) {
    const p = parseControl(id, level);
    out.push(p ? `<span class="ctl">${esc(p.id)}</span> ${esc(p.title)} · ${esc(p.requirement ?? '')}` : esc(id));
  }
  return out;
}

function itemBlock(r, level = DEFAULT_COMPLIANCE_LEVEL) {
  const qKeys = r.queries ?? [];
  // 主机侧检查（priv === null）没有 SQL 依据：依据是 SSH 白名单命令，写清楚免得读者以为漏了证据
  const isOs = r.priv === null;
  const qText = isOs
    ? '主机侧只读命令（ps / stat / ss / grep / find；白名单见附录 B）'
    : qKeys.length
      // 用 · 分隔而不是再套一层括号：QUERY_PURPOSE 本身常带括号，套起来会出现
      // `users（账号状态与认证方式（不含口令散列））` 这种双层括号
      ? qKeys.map((q) => `<code>${esc(q)}</code> <span class="muted">·</span> ${esc(QUERY_PURPOSE[q] ?? '')}`).join('　')
      : '—';
  const ctl = controlLabels(r.compliance, r.complianceLevel ?? level);
  const ctlHtml = ctl.length
    ? ctl.map((t) => `<div class="ctl-line">${t}</div>`).join('')
    : r.hardening
      ? `<div class="ctl-line"><span class="ctl hard">加固项</span> ${inline(r.hardening)}</div>`
      : '';
  return (
    `<article class="item ${r.level}">` +
    `<div class="item-head">` +
    `<span class="badge ${r.level}">${LEVEL_LABEL[r.level]}</span>` +
    `<span class="item-title">${esc(r.title)}</span>` +
    // 级别差异导致的不适用：把「第 N 级起要求」直接打在标题旁，避免被读成本级的安全缺陷
    (r.levelApplicability === 'below-level' ? `<span class="pill lvl">第 ${r.minLevel} 级起要求</span>` : '') +
    `<span class="item-id">${esc(r.id)}</span>` +
    `</div>` +
    `<div class="item-body">${inline(r.message)}</div>` +
    listBlock(r.items) +
    (r.advice ? `<div class="advice"><span class="advice-tag">整改建议</span>${inline(r.advice)}</div>` : '') +
    `<div class="item-foot"><span><i>依据</i>${qText}</span><span><i>所需权限</i>${esc(r.priv ?? '—（走 SSH，不要求库权限）')}</span></div>` +
    ctlHtml +
    (r.evidence?.length ? `<details class="ev-details"><summary>查看证据（${r.evidence.length} 行）</summary>${evidenceTable(r.evidence)}</details>` : '') +
    `</article>`
  );
}

const LEVEL_MEANING = {
  crit: '直接违反硬性要求或造成实质暴露，需优先整改',
  warn: '偏离基线或存在真实风险，建议按计划整改',
  ok: '已满足该项基线要求',
  info: '仅陈述事实或能力发现，不构成不符合',
  na: '本版本 / 本形态不提供该能力，**不计为不符合**',
  unknown: '本次未取得数据（权限不足、字典不存在或需 OS 侧），**既不代表符合也不代表不符合**',
};

/** 结论看板：KPI 卡片 + 分布条 + 含义表（数字一眼可见，含义可查）。 */
function dashboard(counts, assessed) {
  const total = LEVEL_ORDER.reduce((a, lv) => a + (counts[lv] ?? 0), 0);
  const kpi = LEVEL_ORDER.map(
    (lv) => `<div class="kpi ${lv}"><div class="kpi-n">${counts[lv] ?? 0}</div><div class="kpi-t">${LEVEL_LABEL[lv]}</div></div>`,
  ).join('');
  const segs = LEVEL_ORDER.filter((lv) => (counts[lv] ?? 0) > 0)
    .map((lv) => `<span class="seg ${lv}" style="flex:${counts[lv]}" title="${LEVEL_LABEL[lv]} ${counts[lv]}"></span>`)
    .join('');
  const rows = LEVEL_ORDER.map(
    (lv) =>
      `<tr><td><span class="badge ${lv}">${LEVEL_LABEL[lv]}</span></td><td class="n">${counts[lv] ?? 0}</td><td class="mean">${inline(LEVEL_MEANING[lv])}</td></tr>`,
  ).join('');
  return (
    `<div class="board">` +
    `<div class="kpis">${kpi}</div>` +
    `<div class="distbar">${segs}</div>` +
    `<div class="board-foot">共 ${total} 项检查，其中 <b>已判定 ${assessed} 项</b>（严重 + 警告 + 合规）；不适用与未取到不计入。</div>` +
    `</div>` +
    `<table class="matrix"><thead><tr><th style="width:96px">结论</th><th class="n">项数</th><th>判定含义</th></tr></thead><tbody>${rows}</tbody></table>`
  );
}

const CHARSET_BY_FLAG = { 0: 'GB18030', 1: 'UTF-8', 2: 'EUC-KR' };

/**
 * `V$DATABASE.ROLE$` / `ARCH_MODE` 是**码值**，得翻译成人话再展示
 * （解码表取自 02 组 `basic.database`：0=NORMAL / 1=PRIMARY / 2=STANDBY；ARCH_MODE 'Y'=归档）。
 * 真机上直接显示原始值会出现「库角色 0　归档 Y」这种看不懂的行。
 */
const ROLE_LABEL = { 0: 'NORMAL（单机 / 非主备）', 1: 'PRIMARY（主库）', 2: 'STANDBY（备库）' };
export function roleLabel(role) {
  if (role === null || role === undefined || role === '') return null;
  const n = Number(role);
  return Number.isFinite(n) && ROLE_LABEL[n] ? ROLE_LABEL[n] : String(role);
}
export function archLabel(arch) {
  if (arch === null || arch === undefined || arch === '') return null;
  return String(arch).trim().toUpperCase() === 'Y' ? 'ARCHIVELOG（已开启归档）' : 'NOARCHIVELOG（非归档）';
}

/** 授权剩余天数的状态（与 02 组 basic.license 同口径：<0 过期 / <30 严重 / <90 提醒）。 */
function licenseCell(lic) {
  if (!lic || lic.expiredDate == null) return '未取到（需要 SYSDBA/DBA 权限）';
  const d = lic.daysLeft;
  const tag =
    lic.state === 'expired' ? `<span class="badge crit">已过期</span>`
    : lic.state === 'crit' ? `<span class="badge crit">仅剩 ${d} 天</span>`
    : lic.state === 'warn' ? `<span class="badge warn">剩余 ${d} 天</span>`
    : lic.state === 'ok' ? `<span class="badge ok">剩余 ${d} 天</span>`
    : '—';
  return `${tag} <span class="muted">到期日</span> <b>${esc(lic.expiredDate)}</b>`;
}

/** 版本号的取值证据：原始 SQL + 原始行，便于复核「8.1.5.60 是怎么算出来的」。 */
function versionEvidenceBlock(ev) {
  const row = ev?.row ?? {};
  const keys = Object.keys(row);
  const table = keys.length
    ? `<table class="ev"><thead><tr>${keys.map((k) => `<th>${esc(k)}</th>`).join('')}</tr></thead><tbody><tr>${keys
        .map((k) => `<td>${esc(row[k] ?? '—')}</td>`)
        .join('')}</tr></tbody></table>`
    : '';
  return (
    (ev?.sql ? `<pre class="sql">${esc(ev.sql)}</pre>` : '') +
    table +
    `<div class="note">四位内核版本号由 <code>ID_CODE</code> 的十六进制片段解出（取法与 02 组巡检插件一致）。
    上面这条就是插件实际执行的语句，可与人工在 disql 中的执行结果逐字对照；
    <code>SVR_VERSION</code> 只到「V8」，不能作为精确版本。若某版本不接受该形态，插件会自动降级到
    显式 <code>FROM V$INSTANCE</code> 形态（见 <code>lib/queries.js</code> 的降级链）。</div>`
  );
}

/**
 * 构建号与 ID_CODE 的关系。
 *
 * ★ 2026-10-12 按用户反馈修：报告里「数据库版本 … 构建 03134284604-20260707-…」与
 *   「ID_CODE --03134284604-20260707-…」**是同一串**（ID_CODE 只多两个前缀 `--`），
 *   并列两行属于重复。实测（单实例 + DMDSC 两节点）三者一致，故：
 *     · 等价时**合并成一行**并说明关系；
 *     · 不等价时（别的版本可能不同）**照旧两行都给**，不丢信息。
 */
function versionIdParts(meta) {
  const build = meta.build ? String(meta.build).trim() : null;
  const idCode = meta.idCode ? String(meta.idCode).trim() : null;
  const same = Boolean(build && idCode && idCode.replace(/^-+/, '') === build);
  return { build, idCode, same };
}

/** 版本标识单元格（HTML）。 */
function versionIdCell(meta) {
  const { build, idCode, same } = versionIdParts(meta);
  if (!build && !idCode) return '未取到';
  if (same) return `<code>${esc(build)}</code> <span class="muted">（ID_CODE 为同一串，仅多前缀 <code>--</code>，故合并为本行）</span>`;
  return [build ? `构建 <code>${esc(build)}</code>` : null, idCode ? `ID_CODE <code>${esc(idCode)}</code>` : null].filter(Boolean).join('　·　');
}

/**
 * 评估概况 + 版本与实例信息两块键值表。
 * 版本块**取法与展示对齐 02 组巡检插件的「基础信息」一组**：版本类型与四位内核版本号都由
 * `ID_CODE` 解出（不是从 SVR_VERSION 猜），并给出启动时间、字符集/页大小、授权剩余天数。
 */
function metaTables(meta, extra) {
  const row = (k, v) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`;
  const cs = meta.charset ?? {};
  const uf = cs.unicodeFlag === null || cs.unicodeFlag === undefined ? null : Number(cs.unicodeFlag);
  const charsetName = uf === null ? '未取到' : CHARSET_BY_FLAG[uf] ?? `未知(${uf})`;
  const page = cs.pageSizeBytes === null || cs.pageSizeBytes === undefined ? null : Number(cs.pageSizeBytes);
  const runTxt =
    meta.runDays === null || meta.runDays === undefined
      ? '—'
      : Number(meta.runDays) < 1
        ? `约 ${Math.round(Number(meta.runDays) * 1440)} 分钟`
        : `约 ${Number(meta.runDays)} 天`;

  const overview = `<table class="meta"><tbody>${[
    row('评估对象', `<b>${esc(meta.target ?? '—')}</b>　<span class="muted">数据库</span> ${esc(meta.dbName ?? '—')}`),
    row('采集账号', `<b>${esc(meta.account ?? '—')}</b>`),
    row('权限层判定', esc(meta.privSource ?? '—')),
    // ⚠️ 必须 map 成 row()：直接 `...extra` 展开的是「数组元素」，
    //    而 Array.join('') 会把嵌套数组 toString 成逗号串，把三行挤成一坨（截图才发现的）。
    ...extra.map(([k, v]) => row(k, v)),
  ].join('')}</tbody></table>`;

  const version = `<table class="meta"><tbody>${[
    row('版本类型', `<b>${esc(meta.edition ?? '未取到')}</b>${meta.edition ? ' <span class="muted">由 ID_CODE 解码</span>' : ''}`),
    row('内核版本号', meta.innerVersion ? `<b class="num">${esc(meta.innerVersion)}</b> <span class="muted">四位，由 ID_CODE 解出</span>` : '未取到'),
    // 构建号与 ID_CODE 合并成一行（等价时；见 versionIdParts 的说明），避免同一串占两行
    row('数据库版本', esc(meta.version ?? '—')),
    row('构建 / ID_CODE', versionIdCell(meta)),
    row('实例 / 主机', `${esc(meta.instanceName ?? '—')} / ${esc(meta.hostName ?? '—')}`),
    row(
      '部署形态',
      `${esc(meta.cluster ?? '—')}${meta.epNames?.length ? `（节点 ${meta.epNames.map((n) => esc(n)).join('、')}）` : ''}${roleLabel(meta.role) ? ` · ${esc(roleLabel(meta.role))}` : ''}${archLabel(meta.archMode) ? ` · ${esc(archLabel(meta.archMode))}` : ''}`,
    ),
    row('启动时间 / 运行时长', `${esc(meta.startTime ?? '—')} <span class="muted">/</span> ${esc(runTxt)}`),
    row(
      '字符集 / 页大小',
      `${esc(charsetName)} · 页大小 ${page === null ? '—' : `${page} 字节`} · 簇大小 ${esc(cs.extentSize ?? '—')} · 大小写${Number(cs.caseSensitive) === 1 ? '敏感' : '不敏感'}` +
        (page !== null && page < 8192 ? ' <span class="badge warn">页大小小于 8K</span>' : ''),
    ),
    row('授权有效期', licenseCell(meta.license)),
    row(
      '授权版本范围',
      meta.license
        ? `${esc(meta.license.serverVer ?? '—')}${meta.license.maxCpu ? ` · 最大 CPU ${esc(meta.license.maxCpu)}` : ''}${meta.license.customer ? ` · 客户 ${esc(meta.license.customer)}` : ''}`
        : '未取到',
    ),
    row('职责分离形态', esc(meta.privMode ?? '未取得（普通版无此类配置）')),
    row('安全版能力信号', meta.secure ? esc((meta.secureSignals ?? []).join('；')) : '未检测到（普通版不提供强制访问控制）'),
  ].join('')}</tbody></table>`;

  return { overview, version };
}

/** 章节标题（编号 chip + 标题 + 右侧细线）。 */
const sectionHead = (id, no, title, { backLink = true } = {}) =>
  `<h2 id="${id}"><span class="hno">${esc(no)}</span><span class="ht">${esc(title)}</span>` +
  // 「↑ 目录」回跳：报告很长时，从任意章节回到目录只差一次点击（纯锚点，无脚本）
  (backLink ? `<a class="totop" href="#toc">↑ 目录</a>` : '') +
  `</h2>`;

/**
 * @param {object} o
 * @param {object} o.meta        头部元信息（目标/账号/版本/形态…）
 * @param {object} o.result      runChecks() 的返回值
 * @param {object} [o.snapshots] 原始采集结果（用于附录的参数快照）
 * @param {string} o.generatedAt
 * @param {string} [o.disclaimer]
 * @param {string} [o.driver]    'jdbc' | 'demo'
 */
export function buildReportHtml({ meta = {}, result, snapshots = {}, generatedAt = '', disclaimer = '', driver = 'jdbc', nodeConsistency = null }) {
  const counts = result.counts;
  const top = topActions(result.results, 8);
  const byDomain = DOMAINS.map((d) => ({ ...d, items: result.results.filter((r) => r.domain === d.key) })).filter((d) => d.items.length);
  const domainStat = (items) =>
    LEVEL_ORDER.filter((lv) => items.some((r) => r.level === lv))
      .map((lv) => `<span class="mini ${lv}">${LEVEL_LABEL[lv]} <b>${items.filter((r) => r.level === lv).length}</b></span>`)
      .join('');
  const reportId = `DM-SEC-${String(generatedAt).replace(/[^0-9]/g, '').slice(0, 14) || 'X'}`;

  // ---- 等保对照级别：决定标题、条款编号（二级 7.1.4.x / 三级 8.1.4.x / 四级 9.1.4.x）与级别口径说明 ----
  const lv = normalizeLevel(result.complianceLevel);
  const lvm = levelMeta(lv);
  const basis = levelBasis(lv);
  const naByLevel = result.naByLevelItems ?? result.results.filter((r) => r.levelApplicability === 'below-level');
  const LVL_TITLE = `等保 2.0 ${lvm.short}控制点对照`;

  const paramRows = (snapshots.params?.rows ?? []).map((r) => ({
    参数: r.PARA_NAME,
    当前值: r.PARA_VALUE,
    文件值: r.FILE_VALUE ?? '—',
    默认值: r.DEFAULT_VALUE ?? '—',
    说明: String(r.DESCRIPTION ?? '').slice(0, 70),
  }));

  /**
   * 目录（TOC）。
   *
   * 两层：章节 + 章内锚点（分域各域、等保对照各章条）。纯 CSS 实现 ——
   * 报告坚持**零外部依赖、零 `<script>`**（自检里有断言），所以用 `href="#id"` 锚点 +
   * `scroll-behavior:smooth` + `:target` 高亮；每个章节标题旁还有「↑ 目录」回跳。
   */
  const toc = [
    ['s1', '1', '评估概况'],
    ['s2', '2', '结论摘要'],
    ['s3', '3', '分域明细'],
    ['s4', '4', LVL_TITLE],
    result.hardeningItems?.length ? ['s5', '5', '加固项（不映射等保条款）'] : null,
    ['s6', '6', `未闭环清单（${result.openItems.length} 项）`],
    ['s7', 'A', '附录 A · 安全相关参数快照'],
    ['s8', 'B', '附录 B · 评估方法与局限'],
  ].filter(Boolean);
  /**
   * 等保**章条**级锚点 id：只由章条号派生（`8.1.4.1(a)` → `c-8_1_4_1`）。
   *
   * ★ 这里踩过一次坑（自检的「目录锚点全部指向存在的 id」断言当场抓到）：
   *   目录子条目原本用 `new Map([...]).values()` 取「每组第一条」，而 Map 对重复键的语义是
   *   **值取最后一个、位置留在第一个** —— 于是目录拿到了每组的最后一个字母（`c-8_1_4_1_c_`），
   *   而锚点打在该组的第一行（`c-8_1_4_1_a_`）→ 5 条断链。改成两边都用**章条级 id** 后彻底对齐。
   */
  const clauseId = (control) => `c-${String(control).replace(/\([a-z]\)$/, '').replace(/\./g, '_')}`;
  const clauseNo = (control) => (String(control).match(/\.(\d+)\(/) ?? [, '?'])[1];
  /** 章内子条目：分域各域 + 等保各章条（后者按 8.1.4.x 分组，锚点打在每组第一行上）。 */
  const tocSub = {
    s3: byDomain.map((d) => [`d-${d.key}`, d.order, `${d.title}（${d.items.length} 项）`]),
    s4: [...new Set(result.compliance.map((c) => c.control.replace(/\([a-z]\)$/, '')))].map((g) => [
      clauseId(g),
      clauseNo(g),
      `${g} ${result.compliance.find((c) => c.control.startsWith(g))?.title ?? ''}`,
    ]),
  };
  /** 等保表格里每个章条的第一行挂锚点，供目录子条目跳转。 */
  const clauseAnchorSeen = new Set();
  const clauseAnchor = (control) => {
    const id = clauseId(control);
    if (clauseAnchorSeen.has(id)) return '';
    clauseAnchorSeen.add(id);
    return ` id="${id}"`;
  };
  /** 目录本体：两层列表，纯 CSS 两栏排版（窄屏一栏），全部是 `#锚点` 链接。 */
  const tocHtml = `<div class="toccard" id="toc">
    <div class="toc-title">目录　<span class="muted">点击条目跳转到对应章节；每个章节标题右侧有「↑ 目录」可回跳</span></div>
    <ol class="toc2">
      ${toc
        .map(([id, no, t]) => {
          const sub = tocSub[id] ?? [];
          return (
            `<li><a href="#${id}"><span class="tn">${esc(no)}</span>${esc(t)}</a>` +
            (sub.length
              ? `<ul class="toc2-sub">${sub
                  .map(([sid, sno, st]) => `<li><a href="#${sid}"><span class="tn">${esc(sno)}</span>${esc(st)}</a></li>`)
                  .join('')}</ul>`
              : '') +
            `</li>`
          );
        })
        .join('')}
    </ol>
  </div>`;

  const cs = meta.charset ?? {};
  const versionLine = `${esc(meta.edition ?? '—')} ${esc(meta.innerVersion ?? '')}`.trim();

  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="达梦数据库安全配置评估报告 · ${esc(meta.dbName ?? '')} · ${esc(generatedAt)}">
<title>达梦数据库安全评估报告 · ${esc(meta.dbName ?? '')} · ${esc(generatedAt)}</title>
<style>
  :root{
    --ink:#0b1f33; --ink2:#33475f; --mute:#6b7c93; --faint:#93a2b5;
    --line:#dfe6ee; --line2:#eef2f7; --bg:#eef1f5; --paper:#fff;
    --brand:#12395c; --brand2:#1f5c99; --accent:#c8963e;
    --crit:#b42318; --warn:#b54708; --ok:#067647; --info:#175cd3; --na:#5b6b7f; --unknown:#6941c6;
    --critbg:#fef3f2; --warnbg:#fffaeb; --okbg:#f0fdf4; --infobg:#eff6ff; --nabg:#f6f8fa; --unknownbg:#f7f5ff;
    --radius:8px;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei","PingFang SC","Hiragino Sans GB",sans-serif;
    --mono:ui-monospace,SFMono-Regular,"SF Mono",Consolas,"Liberation Mono",monospace;
  }
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
  /* 锚点跳转后目标不要贴着视口顶端；点目录跳过去要能一眼看到落在哪 */
  h2[id],h3[id],tr[id]{scroll-margin-top:14px}
  :target{background:#fff9e6;outline:1px solid #f0d9a0;border-radius:4px}
  tr:target td{background:#fff9e6 !important}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
       font-size:14px;line-height:1.68;font-variant-numeric:tabular-nums}
  .sheet{max-width:1120px;margin:0 auto;background:var(--paper);box-shadow:0 1px 3px rgba(11,31,51,.08),0 12px 40px rgba(11,31,51,.06)}
  .wrap{padding:0 44px 56px}
  code{background:#f1f4f8;border:1px solid var(--line2);padding:0 4px;border-radius:3px;font-size:12.5px;font-family:var(--mono)}
  b{color:#08192b}
  .muted{color:var(--mute);font-weight:400}
  a{color:var(--brand2);text-decoration:none} a:hover{text-decoration:underline}

  /* ============ 封面信息带 ============ */
  .cover{background:linear-gradient(135deg,#0d2b47 0%,#12395c 55%,#1b4b74 100%);color:#eaf1f8;padding:40px 44px 30px}
  .cover-kicker{font-size:11.5px;letter-spacing:3px;text-transform:uppercase;color:#8fb4d6}
  .cover-title{font-size:30px;font-weight:700;margin:10px 0 2px;letter-spacing:1px;color:#fff}
  .cover-sub{font-size:12.5px;letter-spacing:1.6px;color:#a9c6e0;text-transform:uppercase}
  .cover-rule{height:3px;width:64px;background:var(--accent);margin:16px 0 20px;border-radius:2px}
  .cover-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(196px,1fr));gap:12px 28px}
  .cover-facts div{font-size:12.5px;color:#9fbdd8}
  .cover-facts b{display:block;color:#fff;font-size:14.5px;font-weight:600;margin-top:2px;letter-spacing:.2px}
  .cover-demo{margin-top:18px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.28);
              border-radius:6px;padding:9px 13px;font-size:12.5px;color:#ffe6e6}

  /* ============ 章节 ============ */
  h2{display:flex;align-items:center;gap:12px;font-size:16px;margin:42px 0 14px;letter-spacing:.4px;color:var(--brand)}
  h2 .hno{flex:0 0 auto;width:26px;height:26px;border-radius:6px;background:var(--brand);color:#fff;
          font-size:12.5px;font-weight:700;display:flex;align-items:center;justify-content:center;letter-spacing:0}
  h2 .ht{flex:0 0 auto}
  h2::after{content:"";flex:1 1 auto;height:1px;background:var(--line)}
  h3{font-size:14.5px;margin:26px 0 10px;color:var(--ink);display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  h3 .hno{color:var(--faint);font-family:var(--mono);font-size:12.5px}
  h3 .mini{margin-left:auto}
  .card{background:var(--paper);border:1px solid var(--line);border-radius:var(--radius);padding:16px 18px;margin:12px 0}
  .note{font-size:12.5px;color:var(--mute);margin:8px 0 0}

  /* ============ 目录 ============ */
  ul.toc{list-style:none;margin:14px 0 0;padding:14px 18px;display:grid;
         grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:6px 22px;
         background:#f8fafc;border:1px solid var(--line);border-radius:var(--radius)}
  ul.toc li{font-size:13px;display:flex;gap:8px;align-items:baseline}
  ul.toc .tn{color:var(--faint);font-family:var(--mono);font-size:11.5px}

  /* ============ 结论看板 ============ */
  .board{margin:14px 0 6px}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:10px}
  .kpi{border:1px solid var(--line);border-radius:var(--radius);padding:12px 14px;background:#fbfcfe}
  .kpi-n{font-size:26px;font-weight:700;line-height:1.1;letter-spacing:-.5px}
  .kpi-t{font-size:12px;color:var(--mute);margin-top:2px}
  .kpi.crit{background:var(--critbg);border-color:#f6d3d0} .kpi.crit .kpi-n{color:var(--crit)}
  .kpi.warn{background:var(--warnbg);border-color:#f3e0bd} .kpi.warn .kpi-n{color:var(--warn)}
  .kpi.ok{background:var(--okbg);border-color:#c9ebd6} .kpi.ok .kpi-n{color:var(--ok)}
  .kpi.info{background:var(--infobg);border-color:#cfdffb} .kpi.info .kpi-n{color:var(--info)}
  .kpi.na{background:var(--nabg);border-color:var(--line)} .kpi.na .kpi-n{color:var(--na)}
  .kpi.unknown{background:var(--unknownbg);border-color:#ddd3f7} .kpi.unknown .kpi-n{color:var(--unknown)}
  .distbar{display:flex;height:12px;border-radius:6px;overflow:hidden;margin:14px 0 8px;background:var(--line2)}
  .seg{display:block;height:100%}
  .seg.crit{background:var(--crit)} .seg.warn{background:var(--warn)} .seg.ok{background:var(--ok)}
  .seg.info{background:var(--info)} .seg.na{background:#a9b6c6} .seg.unknown{background:var(--unknown)}
  .board-foot{font-size:12.5px;color:var(--mute)}

  /* ============ 表格 ============ */
  table{border-collapse:collapse;width:100%;font-size:13px;margin:12px 0}
  th,td{padding:8px 11px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line2)}
  thead th{background:#f8fafc;color:var(--ink2);font-weight:600;border-bottom:1px solid var(--line);
           font-size:12.5px;letter-spacing:.2px}
  tbody tr:nth-child(even){background:#fcfdfe}
  tbody tr:hover{background:#f7fafd}
  table.meta th{width:150px;background:#f8fafc;color:var(--ink2);font-weight:600;border-bottom:1px solid var(--line2)}
  table.meta td{color:var(--ink)}
  table.matrix td.n,table.matrix th.n{width:62px;text-align:right;font-weight:600}
  table.matrix td.mean{color:var(--ink2)}
  table.ev{font-size:12.5px;margin:4px 0}
  table.ev th{position:sticky;top:0}
  .ev-wrap{max-height:340px;overflow:auto;border:1px solid var(--line);border-radius:6px}
  ul.items{list-style:none;margin:8px 0 10px;padding:0 0 0 14px;border-left:2px solid var(--line)}
  ul.items li{font-size:13.5px;margin:3px 0;color:var(--ink2);position:relative;padding-left:12px}
  ul.items li::before{content:"";position:absolute;left:0;top:.62em;width:5px;height:5px;border-radius:50%;background:var(--faint)}

  /* ============ 徽章 ============ */
  .badge{display:inline-block;font-size:11.5px;line-height:19px;padding:0 9px;border-radius:10px;color:#fff;
         font-weight:600;letter-spacing:.3px;white-space:nowrap}
  .badge.crit{background:var(--crit)} .badge.warn{background:var(--warn)} .badge.ok{background:var(--ok)}
  .badge.info{background:var(--info)} .badge.na{background:var(--na)} .badge.unknown{background:var(--unknown)}
  .mini{display:inline-block;font-size:11.5px;padding:1px 8px;border-radius:9px;font-weight:600;white-space:nowrap}
  .mini b{font-weight:700}
  .mini.crit{background:var(--critbg);color:var(--crit)} .mini.warn{background:var(--warnbg);color:var(--warn)}
  .mini.ok{background:var(--okbg);color:var(--ok)} .mini.info{background:var(--infobg);color:var(--info)}
  .mini.na{background:var(--nabg);color:var(--na)} .mini.unknown{background:var(--unknownbg);color:var(--unknown)}
  /* 域标题上的「N 项」是计数、不是结论级别，用中性色，避免被读成「合规」 */
  .pill{display:inline-block;font-size:11.5px;padding:1px 8px;border-radius:9px;font-weight:600;
        background:#f1f4f8;color:var(--mute);border:1px solid var(--line)}
  /* 「第 N 级起要求」标记：把「级别差异导致的 na」与「产品形态导致的 na」在视觉上区分开 */
  .pill.lvl{background:#eef4ff;color:#1f5c99;border-color:#cfe0f7}
  /* ============ 目录（TOC）：纯 CSS 两栏 + 锚点跳转，不用脚本 ============ */
  .toccard{border:1px solid var(--line);border-radius:var(--radius);background:linear-gradient(180deg,#fbfcfe,#fff);
           padding:14px 18px;margin:16px 0 4px}
  .toc-title{font-weight:700;color:var(--brand);letter-spacing:.5px;margin-bottom:10px;font-size:14px}
  .toc-title .muted{font-weight:400;font-size:12px;letter-spacing:0}
  ol.toc2{margin:0;padding:0;list-style:none;columns:2;column-gap:30px}
  ol.toc2>li{break-inside:avoid;margin:0 0 8px}
  ol.toc2>li>a{display:block;font-weight:600;color:var(--ink);font-size:13.5px}
  ol.toc2>li>a:hover{color:var(--brand2)}
  ol.toc2 .tn{display:inline-block;min-width:22px;margin-right:6px;color:var(--brand2);
              font-family:var(--mono);font-size:12px}
  ul.toc2-sub{margin:3px 0 0;padding:0 0 0 28px;list-style:none}
  ul.toc2-sub li{margin:2px 0;break-inside:avoid}
  ul.toc2-sub a{font-size:12.5px;color:var(--ink2)}
  ul.toc2-sub a:hover{color:var(--brand2)}
  a.totop{float:right;font-size:12px;font-weight:400;color:var(--mute)}
  a.totop:hover{color:var(--brand2)}
  @media (max-width:860px){ ol.toc2{columns:1} }
  /* 等保对照表：本级不适用的行整行压淡，避免被读成本级的合规缺口 */
  tr.row-na td{background:var(--nabg);color:var(--ink2)}
  /* 条款级符合性 chip：与「六态」区分开 —— 前者是条款级归纳，后者是单项结论 */
  .confchip{display:inline-block;font-size:11.5px;line-height:19px;padding:0 9px;border-radius:10px;font-weight:600;white-space:nowrap}
  .confchip b{font-weight:700}
  .confchip.pass{background:var(--okbg);color:var(--ok);border:1px solid #b7e4c7}
  .confchip.partial{background:var(--warnbg);color:var(--warn);border:1px solid #f3e0bd}
  .confchip.fail{background:var(--critbg);color:var(--crit);border:1px solid #f5c2bd}
  .confchip.na{background:var(--nabg);color:var(--na);border:1px solid var(--line)}
  .confchip.pending{background:var(--unknownbg);color:var(--unknown);border:1px solid #d8ccf7}
  .confboard{margin:10px 0 4px}
  .confboard-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:13px}
  th .confchip{font-weight:600}
  ul.lvlnotes{margin:8px 0 0;padding-left:20px;font-size:12.5px;color:var(--mute);line-height:1.7}
  ul.lvlnotes li{margin:3px 0}

  /* ============ 检查项卡片 ============ */
  article.item{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:var(--radius);
               padding:13px 16px;margin:10px 0;background:var(--paper)}
  article.item.crit{border-left-color:var(--crit);background:linear-gradient(90deg,var(--critbg),#fff 42%)}
  article.item.warn{border-left-color:var(--warn);background:linear-gradient(90deg,var(--warnbg),#fff 42%)}
  article.item.ok{border-left-color:var(--ok);background:linear-gradient(90deg,var(--okbg),#fff 42%)}
  article.item.info{border-left-color:var(--info);background:linear-gradient(90deg,var(--infobg),#fff 42%)}
  article.item.na{border-left-color:#a9b6c6;background:var(--nabg)}
  article.item.unknown{border-left-color:var(--unknown);background:linear-gradient(90deg,var(--unknownbg),#fff 42%)}
  .item-head{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap}
  .item-title{font-weight:600;font-size:14px;color:#0b1f33}
  .item-id{margin-left:auto;color:var(--faint);font-size:11.5px;font-family:var(--mono)}
  .item-body{margin:7px 0 0;font-size:13.8px}
  .advice{font-size:13px;color:#6b4400;background:var(--warnbg);border:1px solid #f3e0bd;
          border-radius:6px;padding:8px 12px;margin:10px 0 0}
  .advice-tag{display:inline-block;font-weight:700;font-size:11.5px;letter-spacing:.5px;
              color:#8a5a00;margin-right:8px;text-transform:uppercase}
  .item-foot{display:flex;flex-wrap:wrap;gap:6px 20px;font-size:12px;color:var(--mute);
             margin-top:10px;padding-top:8px;border-top:1px solid var(--line2)}
  .item-foot i{font-style:normal;color:var(--faint);margin-right:6px}
  .ctl-line{font-size:12px;color:var(--ink2);margin-top:5px;line-height:1.6}
  .ctl{display:inline-block;font-family:var(--mono);font-size:11.5px;background:#f1f4f8;border:1px solid var(--line);
       border-radius:3px;padding:0 5px;margin-right:6px;color:var(--brand)}
  .ctl.hard{background:var(--warnbg);border-color:#f3e0bd;color:#8a5a00;font-family:var(--sans);font-weight:600}
  details{margin-top:9px} summary{cursor:pointer;font-size:12.5px;color:var(--brand2);list-style:none}
  pre.sql{margin:8px 0;padding:11px 13px;background:#0f2136;color:#dbe7f3;border-radius:6px;
          font-family:var(--mono);font-size:12px;line-height:1.6;overflow:auto;white-space:pre;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  summary::-webkit-details-marker{display:none}
  summary::before{content:"▸ ";color:var(--faint)}
  details[open] summary::before{content:"▾ "}

  .disc{font-size:12.5px;color:var(--ink2);background:#f8fafc;border:1px solid var(--line);
        border-left:3px solid var(--accent);border-radius:6px;padding:14px 16px}
  .disc p{margin:6px 0}
  .rpt-foot{margin-top:40px;padding-top:14px;border-top:2px solid var(--brand);
            display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--mute)}

  /* ============ 打印（A4）============ */
  @page{size:A4;margin:15mm 13mm}
  @media print{
    body{background:#fff;font-size:11.5pt}
    .sheet{max-width:none;box-shadow:none}
    .wrap{padding:0 0 8mm}
    .cover{padding:22mm 12mm 12mm;-webkit-print-color-adjust:exact;print-color-adjust:exact}
    ul.toc{display:none}
    h2{break-after:avoid;margin-top:22px}
    h3{break-after:avoid}
    article.item,table,.board{break-inside:avoid}
    tbody tr:hover{background:transparent}
    details{display:block}
    details>summary{display:none}
    details>*{display:block}
    .ev-wrap{max-height:none;overflow:visible}
    a{color:inherit;text-decoration:none}
    .rpt-foot{position:running(foot)}
  }
</style></head>
<body><div class="sheet">

  <header class="cover">
    <div class="cover-kicker">Dameng DM8 · Security Configuration Assessment</div>
    <div class="cover-title">达梦数据库安全评估报告</div>
    <div class="cover-sub">安全配置合规性评估 · 等保 2.0 ${esc(lvm.short)}对照</div>
    <div class="cover-rule"></div>
    <div class="cover-facts">
      <div>评估对象<b>${esc(meta.target ?? '—')}</b></div>
      <div>数据库 / 实例<b>${esc(meta.dbName ?? '—')} / ${esc(meta.instanceName ?? '—')}</b></div>
      <div>版本类型 / 内核<b>${versionLine || '—'}</b></div>
      <div>采集账号<b>${esc(meta.account ?? '—')}</b></div>
      <div>生成时间<b>${esc(generatedAt)}</b></div>
      <div>报告编号<b>${esc(reportId)}</b></div>
    </div>
    ${driver === 'demo' ? '<div class="cover-demo"><b>本报告使用内置演示数据生成，不对应任何真实数据库</b>，仅用于展示报告形态与判定分支。</div>' : ''}
  </header>

  <div class="wrap">

  ${tocHtml}

  ${sectionHead('s1', '1', '评估概况')}
  <div class="card">${metaTables(meta, [
    ['数据来源', driver === 'demo' ? '内置演示数据（不连库）' : '只读 JDBC 采集（桥只放行 SELECT / WITH）'],
    ['评估标准', esc(standardName(lv))],
    ['等保对照级别', `<b>第 ${lv} 级（${esc(lvm.label)}）</b> <span class="muted">· 由调用参数 level 指定，默认第三级</span>`],
    ['检查项数', `${result.results.length} 项 / ${byDomain.length} 个域`],
    // 主机侧是否查了、怎么查的：不写清楚，读者会把「没查」读成「没问题」
    ['OS 访问', meta.osAccess ? esc(meta.osAccess) : '未启用（纯 JDBC 只读）'],
  ]).overview}</div>
  <h3>版本与实例信息</h3>
  <div class="card">${metaTables(meta, []).version}</div>
  ${nodeConsistency?.labels?.length > 1 ? `<h3>节点间配置一致性（DMDSC）</h3>${renderConsistencyHtml(nodeConsistency)}` : ''}
  ${
    meta.versionEvidence?.sql
      ? `<details class="ev-details"><summary>版本号是怎么算出来的（原始 SQL + 取值）</summary>${versionEvidenceBlock(meta.versionEvidence)}</details>`
      : ''
  }
  <div class="note">版本类型与四位内核版本号均由 <code>ID_CODE</code> 解码（取法与 02 组巡检插件的「基础信息」一致，不是从 <code>SVR_VERSION</code> 猜的）；
  授权到期后实例将无法启动，剩余不足 90 天即提醒、不足 30 天标红；字符集与页大小建库后不可更改。</div>

  ${sectionHead('s2', '2', '结论摘要')}
  ${dashboard(counts, result.assessed)}
  ${
    naByLevel.length
      ? `<div class="note">级别筛选：本次按<b>第 ${lv} 级（${esc(lvm.label)}）</b>对照，<b>${naByLevel.length} 项</b>为更高等级要求，已判「不适用」且不计入结论统计 —— 这是<b>级别差异</b>，不是安全缺陷：${naByLevel
          .map((r) => `<code>${esc(r.id)}</code>`)
          .join(' ')}。各项的技术结论与整改建议仍保留在明细中，升级定级时可直接复用。</div>`
      : `<div class="note">级别筛选：本次按<b>第 ${lv} 级（${esc(lvm.label)}）</b>对照，没有因级别差异被排除的检查项。</div>`
  }
  <h3>最要紧的几件事</h3>
  ${top.length ? top.map((r) => itemBlock(r, lv)).join('\n') : '<div class="card">没有严重或警告项。</div>'}

  ${sectionHead('s3', '3', '分域明细')}
  ${byDomain
    .map(
      (d) =>
        `<h3 id="d-${d.key}"><span class="hno">${d.order}</span>${esc(d.title)}<span class="pill">${d.items.length} 项</span>${domainStat(d.items)}</h3>` +
        d.items.map((r) => itemBlock(r, lv)).join('\n'),
    )
    .join('\n')}

  ${sectionHead('s4', '4', LVL_TITLE)}
  <div class="note">${inline(basis.basis)}</div>
  <ul class="lvlnotes">${basis.notes.map((n) => `<li>${inline(n)}</li>`).join('')}</ul>
  ${
    // 条款级符合性看板：把「逐项六态」归纳成「这条要求满足没有」，读者不必自己数
    (() => {
      const cc = conformityCounts(result.compliance);
      const total = CONFORMITY_ORDER.reduce((a, k) => a + (cc[k] ?? 0), 0);
      const chips = CONFORMITY_ORDER.map(
        (k) => `<span class="confchip ${k}">${CONFORMITY_LABEL[k]} <b>${cc[k] ?? 0}</b></span>`,
      ).join('');
      return (
        `<div class="card confboard">` +
        `<div class="confboard-head">本轮共对照 <b>${total}</b> 条${esc(lvm.short)}「安全计算环境」条款：${chips}</div>` +
        `<div class="note"><b>符合性是怎么判的</b>：有「严重」→ 不符合；无严重但有「警告」→ 部分符合；` +
        `已核对项全合规且无「未取到」→ 符合；已核对项合规但<b>还有未取到</b>→ 部分符合（证据不全不敢判符合）；` +
        `只有「未取到」或只有「提示」→ 无法判定；只有「不适用」→ 不适用。` +
        `「提示」只是陈述事实（例如「补丁需人工核对」），<b>不构成合规证据</b>。` +
        `这是对本插件<b>能自证范围</b>的归纳，不等于测评机构结论。</div>` +
        `</div>`
      );
    })()
  }
  <div class="note">要求列为<b>摘要</b>（为便于阅读压缩了句式，非标准原文）；章条号与条款字母为工作基线，正式测评以 ${esc(standardName(lv))} 原文及测评机构判定为准。</div>
  <table><thead><tr><th style="width:100px">控制点</th><th>要求（摘要）</th><th style="width:132px">符合性</th><th style="width:76px">适用级别</th><th style="width:74px">最重结论</th><th style="width:236px">涉及检查项（括号内为该单项结论）</th></tr></thead><tbody>
  ${result.compliance
    .map(
      (c) =>
        `<tr${clauseAnchor(c.control)}${c.notApplicableByLevel ? ' class="row-na"' : ''}><td><span class="ctl">${esc(c.control)}</span><div class="note">${esc(c.title ?? '')}</div></td>` +
        `<td>${esc(c.requirement ?? '—')}</td>` +
        `<td><span class="confchip ${c.conformity.key}" title="${esc(c.conformity.reason)}">${CONFORMITY_LABEL[c.conformity.key]}</span><div class="note">${esc(c.conformity.reason)}</div></td>` +
        `<td>${c.minLevel > lv ? `<span class="pill lvl">第 ${c.minLevel} 级起</span>` : `<span class="muted">第 ${c.minLevel} 级起</span>`}</td>` +
        `<td><span class="badge ${c.worst}">${LEVEL_LABEL[c.worst]}</span></td>` +
        `<td>${c.items.map((i) => `<code>${esc(i.id)}</code><span class="mini ${i.level}">${LEVEL_LABEL[i.level]}</span>`).join(' ')}</td></tr>`,
    )
    .join('\n')}
  </tbody></table>

  ${result.hardeningItems?.length
    ? `${sectionHead('s5', '5', '加固项（不映射等保条款）')}
       <div class="note">以下项属安全加固建议，等保 2.0 ${esc(lvm.short)}「安全计算环境」无对应明确条款，列出供参考。</div>
       ${result.hardeningItems.map((r) => itemBlock(r, lv)).join('\n')}`
    : ''}

  ${sectionHead('s6', '6', `未闭环清单（${result.openItems.length} 项）`)}
  ${result.openItems.length
    ? `<div class="card">${result.openItems
        .map(
          (r) =>
            `<article class="item unknown"><div class="item-head"><span class="badge unknown">未取到</span>` +
            `<span class="item-title">${esc(r.title)}</span><span class="item-id">${esc(r.id)}</span></div>` +
            `<div class="item-body">${inline(r.message)}</div>${listBlock(r.items)}` +
            `<div class="item-foot"><span><i>补齐所需权限</i>${esc(r.priv)}</span><span><i>相关查询</i>${esc((r.queries ?? []).join('、') || '—')}</span></div></article>`,
        )
        .join('\n')}</div>`
    : '<div class="card">没有未取到的检查项。</div>'}

  ${sectionHead('s7', 'A', '附录 A · 安全相关参数快照')}
  ${paramRows.length ? evidenceTable(paramRows) : '<div class="card">未取到参数快照。</div>'}

  ${sectionHead('s8', 'B', '附录 B · 评估方法与局限')}
  <div class="card">
    <p><b>方法</b>　以只读 SQL 从数据字典（<code>V$DM_INI</code>、<code>V$INSTANCE</code>、<code>V$LICENSE</code>、
    <code>DBA_USERS</code>、<code>SYSUSERS</code>、<code>DBA_PROFILES</code>、
    <code>DBA_ROLES/SYS_PRIVS/ROLE_PRIVS/TAB_PRIVS</code> 等）采集配置快照，
    按「版本前提 → 权限前提 → 数据是否取到 → 单项判定」四层得出六态结论；不适用与未取到不计入结论统计。</p>
    <p><b>局限</b>　① 结论基于采集时刻的配置快照，参数与权限可能随后变更；
    ② 主机侧（目录权限、进程运行账号、监听绑定、宿主 sshd、审计文件保留）<b>仅在配置了 SSH 时</b>才有结论：
    未配 SSH 时那 7 项判「不适用」，配了但连不上则判「未取到」——两种情况都会写明原因；
    补丁 / 漏洞库仍不在范围（P3）；
    ③ 「未取到」项需按第 6 节补齐权限或人工核对；
    ④ 章条号与要求摘要为工作基线，不代替测评结论；
    ⑤ 等保对照级别由调用参数 <code>level</code> 指定（本次为<b>第 ${lv} 级 · ${esc(lvm.label)}</b>）：级别决定条款编号（二级 7.1.4.x / 三级 8.1.4.x / 四级 9.1.4.x）与要求范围，高等级专属条款在本级判「不适用」，换级别重新评估会得到不同的条款编号与「不适用」清单。</p>
  </div>

  ${sectionHead('s9', 'C', '免责与边界')}
  <div class="disc">${mdToHtml(disclaimer)}</div>

  <footer class="rpt-foot">
    <span>${esc(TOOL_ID)}　·　只读评估，未修改数据库任何配置</span>
    <span>${esc(reportId)}　·　${esc(generatedAt)}</span>
  </footer>
  </div>
</div></body></html>`;
}

/**
 * DSH 工具返回的文本结论（与 HTML 同源，便于在会话里直接读）。
 * 头部固定给出**评估对象与采集账号**（含权限层判定依据）——这是复核结论可信度的前提。
 */
export function renderText(result, meta = {}) {
  const counts = result.counts;
  const lines = [];
  lines.push(`达梦数据库安全评估　${meta.target ?? ''}`.trim());
  lines.push(
    `  评估对象：${meta.dbName ?? '—'} / 实例 ${meta.instanceName ?? '—'}　版本 ${meta.version ?? '—'}${meta.edition ? `（${meta.edition}）` : ''}`,
  );
  lines.push(`  采集账号：${meta.account ?? '—'}　权限层：${meta.privSource ?? '—'}`);
  // 版本与实例信息（取法同 02 组「基础信息」：版本类型与内核版本号由 ID_CODE 解出）
  const lic = meta.license ?? {};
  const uf = meta.charset?.unicodeFlag === null || meta.charset?.unicodeFlag === undefined ? null : Number(meta.charset.unicodeFlag);
  lines.push(`  版本信息：类型 ${meta.edition ?? '未取到'}　内核 ${meta.innerVersion ?? '未取到'}　${meta.version ?? ''}`);
  // 构建号与 ID_CODE 等价时不重复占一行（真机上两者是同一串，ID_CODE 仅多前缀 --）
  {
    const { build, idCode, same } = versionIdParts(meta);
    if (same) lines.push(`  构建 / ID_CODE：${build}（ID_CODE 为同一串，仅多前缀 --）`);
    else if (build || idCode) lines.push(`  ${[build ? `构建 ${build}` : null, idCode ? `ID_CODE ${idCode}` : null].filter(Boolean).join('　')}`);
  }
  lines.push(
    `  实例信息：${meta.instanceName ?? '—'}@${meta.hostName ?? '—'}　启动 ${meta.startTime ?? '—'}${meta.runDays != null ? `（已运行 ${meta.runDays} 天）` : ''}`,
  );
  lines.push(
    `  建库参数：字符集 ${uf === null ? '未取到' : uf === 1 ? 'UTF-8' : uf === 0 ? 'GB18030' : `未知(${uf})`}　页大小 ${meta.charset?.pageSizeBytes ?? '—'} 字节　簇大小 ${meta.charset?.extentSize ?? '—'}　大小写${Number(meta.charset?.caseSensitive) === 1 ? '敏感' : '不敏感'}`,
  );
  lines.push(
    `  授权：${lic.expiredDate ? `到期 ${lic.expiredDate}（剩余 ${lic.daysLeft} 天${lic.state === 'warn' || lic.state === 'crit' || lic.state === 'expired' ? '，**需尽快续期**' : ''}）` : '未取到（需 SYSDBA/DBA 权限）'}${lic.serverVer ? `　授权版本范围 ${lic.serverVer}` : ''}`,
  );
  lines.push(
    `  部署形态：${meta.cluster ?? '—'}${roleLabel(meta.role) ? ` / ${roleLabel(meta.role)}` : ''}${archLabel(meta.archMode) ? ` / ${archLabel(meta.archMode)}` : ''}　检查项 ${result.results.length} 项（已判定 ${result.assessed}）`,
  );
  // 等保对照级别：条款编号的章号随之变化（二级 7.1.4.x / 三级 8.1.4.x / 四级 9.1.4.x）
  const lv = normalizeLevel(result.complianceLevel);
  const lvm = levelMeta(lv);
  lines.push(`  等保对照：第 ${lv} 级（${lvm.label}）　${standardName(lv)}`);
  lines.push(`  OS 访问：${meta.osAccess ?? '未启用（纯 JDBC 只读）'}`);
  // 级别口径也写进文本结论：会话里直接读结论的人不该靠猜「为什么这些项是不适用」
  for (const n of levelBasis(lv).notes) lines.push(`      · ${n.replace(/\*\*/g, '')}`);
  lines.push(
    `  结论分布：严重 ${counts.crit}　警告 ${counts.warn}　合规 ${counts.ok}　提示 ${counts.info}　不适用 ${counts.na}　未取到 ${counts.unknown}`,
  );
  lines.push('  （不适用与未取到不计入已判定；本工具不给出加权评分，结论以逐项判定为准）');
  {
    const below = result.naByLevelItems ?? [];
    if (below.length) {
      lines.push(
        `  级别筛选：按第 ${lv} 级对照，其中 ${below.length} 项属更高等级要求（${below.map((r) => r.id).join('、')}）已判「不适用」——这是级别差异，不是安全缺陷；技术结论仍保留在各条说明里。`,
      );
      for (const r of below) lines.push(`      · ${r.id}：${r.message}`);
    }
  }

  const top = topActions(result.results, 8);
  if (top.length) {
    lines.push('');
    lines.push('最要紧的几件事：');
    for (const r of top) {
      lines.push(`  [${LEVEL_LABEL[r.level]}] ${r.title}（${r.id}）：${r.message}`);
      for (const it of r.items ?? []) lines.push(`      · ${it}`);
      if (r.advice) lines.push(`      整改：${r.advice}`);
    }
  }

  lines.push('');
  lines.push('分域明细：');
  for (const d of DOMAINS) {
    const items = result.results.filter((r) => r.domain === d.key);
    if (!items.length) continue;
    lines.push(`【${d.title}】`);
    for (const r of items) {
      lines.push(`  [${LEVEL_LABEL[r.level]}] ${r.title}：${r.message}`);
      for (const it of r.items ?? []) lines.push(`      · ${it}`);
    }
  }

  if (result.compliance.length) {
    lines.push('');
    lines.push(`等保 2.0 ${lvm.short}控制点对照（${standardName(lv)}，要求为摘要）：`);
    const cc = conformityCounts(result.compliance);
    lines.push(
      `  条款级符合性：符合 ${cc.pass}　部分符合 ${cc.partial}　不符合 ${cc.fail}　不适用 ${cc.na}　无法判定 ${cc.pending}（共 ${result.compliance.length} 条）`,
    );
    lines.push('  （判法：有严重→不符合；无严重有警告→部分符合；已核对项全合规且无未取到→符合；合规但仍有未取到→部分符合；只有未取到或只有提示→无法判定；只有不适用→不适用）');
    for (const c of result.compliance) {
      lines.push(
        `  ${c.control} ${c.title ?? ''} —— **${CONFORMITY_LABEL[c.conformity.key]}**（最重结论 ${LEVEL_LABEL[c.worst]}；${c.count} 项：` +
          `${c.items.map((i) => `${i.id}=${LEVEL_LABEL[i.level]}`).join('、')}）`,
      );
      lines.push(`      依据：${c.conformity.reason}`);
      if (c.requirement) lines.push(`      要求：${c.requirement}`);
    }
  }

  if (result.hardeningItems?.length) {
    lines.push('');
    lines.push(`加固项（不映射等保条款，共 ${result.hardeningItems.length} 项）：${result.hardeningItems.map((r) => r.id).join('、')}`);
  }
  if (result.openItems.length) {
    lines.push('');
    lines.push(`未闭环（${result.openItems.length} 项，需补权限或人工核对）：${result.openItems.map((r) => r.id).join('、')}`);
  }
  return lines.join('\n');
}
