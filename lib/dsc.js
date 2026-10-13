/**
 * DMDSC 多节点支持：节点覆盖度说明 + **节点间安全配置一致性核对**。
 *
 * 为什么需要一致性核对（这是 DSC 独有的安全问题类别）：
 *   DSC 每个节点有**自己的 dm.ini**，`V$DM_INI` 是**按节点返回**的。于是会出现
 *   「A 节点开了审计、B 节点没开」「A 节点关了本地 OS 认证、B 节点开着」这类**跨节点漂移** ——
 *   只出一份份独立报告，人是很难对出来的。`09` 组在恢复能力评估里已用同样的形态解决过同类问题
 *   （`judgeConsistency`），这里沿用其结论，不新造轮子。
 *
 * 口径说明：
 *   · 只比对**与安全判定相关**的参数（就是各检查项真正读的那些），不做全参数 diff；
 *   · 不一致的严重度按参数的安全含义定（审计/认证/加密/口令策略类不一致=严重，其余=警告）；
 *   · 参数在某个节点**不存在**也算不一致（版本/形态差异），单独标注。
 */

import { paramMap } from './analyze.js';

/**
 * 需要跨节点比对的参数。
 * `level` 是**不一致时**的严重度：安全开关类不一致 = 严重（等价于某节点少了一道控制）。
 */
export const NODE_PARAM_KEYS = [
  ['ENABLE_AUDIT', 'crit', '审计开关'],
  ['ENABLE_LOCAL_OSAUTH', 'crit', '本地操作系统认证'],
  ['ENABLE_REMOTE_OSAUTH', 'crit', '远程操作系统认证'],
  ['ENABLE_ENCRYPT', 'crit', '通信加密'],
  ['PWD_POLICY', 'crit', '口令复杂度策略'],
  ['PWD_MIN_LEN', 'crit', '口令最小长度'],
  ['PRIV_FLAG', 'crit', '三权/四权分立'],
  ['GRANT_SCHEMA', 'warn', '模式级授权开关'],
  ['AUDIT_MAX_FILE_SIZE', 'warn', '审计文件大小'],
  ['AUDIT_FILE_FULL_MODE', 'warn', '审计文件写满策略'],
  ['SVR_LOG', 'warn', 'SQL 日志'],
  ['MAX_SESSIONS', 'warn', '实例会话上限'],
];

/** 需要跨节点比对的非参数事实（版本、ID_CODE、归档模式、授权到期日）。 */
const NODE_FACTS = [
  ['version', 'crit', '数据库版本（SVR_VERSION）'],
  ['build', 'crit', '构建号（BUILD_VERSION）'],
  ['idCode', 'crit', 'ID_CODE'],
  ['innerVersion', 'crit', '内核版本号'],
  ['archMode', 'warn', '归档模式'],
];

/**
 * 逐项比对节点间配置。
 *
 * @param {Array<{label:string, data:object, shape:object}>} perNode
 * @returns {{labels:string[], rows:Array, divergent:Array, sameCount:number, absent:Array}}
 */
export function judgeNodeConsistency(perNode) {
  // ⚠️ 2026-10-12 真机教训：调用方给的对象**未必带 label / shape**（assessTarget 返回的是
  //    {data, result, meta}）。当时这里直接读 n.label / n.shape，结果是
  //    「节点标签为空 + 版本/授权那几项静默跳过（只比了 11 个参数）」。
  //    所以这里既容错取值，也**不假设调用方一定补齐** —— 少一个字段就少比一项的设计太脆弱。
  const labelOf = (n) => n.label ?? n.meta?.target ?? n.target ?? '?';
  const shapeOf = (n) => n.shape ?? n.result?.shape ?? {};
  const labels = perNode.map(labelOf);
  const rows = [];
  if (perNode.length < 2) return { labels, rows, divergent: [], sameCount: 0, absent: [] };

  const maps = perNode.map((n) => paramMap(n.data?.params));

  // ① 参数
  for (const [key, level, zh] of NODE_PARAM_KEYS) {
    const cells = maps.map((m, i) => {
      const p = m.get(key);
      return { label: labels[i], present: Boolean(p), raw: p ? String(p.value ?? '').trim() : null, def: p ? String(p.def ?? '') : null };
    });
    const present = cells.filter((c) => c.present);
    // 所有节点都没有这个参数 → 该版本不提供，跳过（不是不一致）
    if (present.length === 0) continue;
    const values = [...new Set(present.map((c) => c.raw))];
    const missing = cells.filter((c) => !c.present).map((c) => c.label);
    const same = values.length === 1 && missing.length === 0;
    rows.push({
      kind: '参数',
      key,
      title: zh,
      cells,
      same,
      level: same ? null : level,
      note: missing.length ? `节点 ${missing.join('、')} 没有该参数` : values.length === 1 ? `各节点一致（${values[0] || '空'}）` : '各节点取值不同',
    });
  }

  // ② 版本等事实
  for (const [field, level, zh] of NODE_FACTS) {
    const cells = perNode.map((n) => {
      const v = shapeOf(n)?.[field];
      return { label: labelOf(n), present: v != null, raw: v == null ? null : String(v) };
    });
    const present = cells.filter((c) => c.present);
    if (present.length === 0) continue;
    const values = [...new Set(present.map((c) => c.raw))];
    const same = values.length === 1;
    rows.push({
      kind: field === 'archMode' ? '配置' : '版本',
      key: field,
      title: zh,
      cells,
      same,
      level: same ? null : level,
      note: same ? `各节点一致` : '各节点不同',
    });
  }

  // ③ 授权到期日（不同节点授权不一致时，可能出现「一个节点先过期」）
  const lic = perNode.map((n) => ({ label: labelOf(n), raw: shapeOf(n)?.license?.expiredDate ?? null }));
  if (lic.some((c) => c.raw)) {
    const values = [...new Set(lic.filter((c) => c.raw).map((c) => c.raw))];
    rows.push({
      kind: '授权',
      key: 'licenseExpired',
      title: '授权到期日',
      cells: lic.map((c) => ({ ...c, present: Boolean(c.raw) })),
      same: values.length === 1,
      level: values.length === 1 ? null : 'warn',
      note: values.length === 1 ? '各节点一致' : '各节点到期日不同（可能各自装了授权文件）',
    });
  }

  const divergent = rows.filter((r) => !r.same);
  const absent = maps.map((m, i) => ({ label: labels[i], size: m.size }));
  return { labels, rows, divergent, sameCount: rows.length - divergent.length, absent };
}

/** 文本块：给工具输出用。 */
export function renderConsistencyText(c) {
  const L = [];
  L.push('');
  L.push(`节点间配置一致性（${c.labels.length} 个节点：${c.labels.join('、')}）`);
  L.push(`  一致 ${c.sameCount} 项，不一致 ${c.divergent.length} 项`);
  if (c.divergent.length === 0) {
    L.push('  ✅ 未发现节点间安全配置漂移。');
    return L.join('\n');
  }
  for (const r of c.divergent) {
    L.push(`  ❌ [${r.level === 'crit' ? '严重' : '警告'}] ${r.title}（${r.key}）`);
    L.push(`      ${r.cells.map((x) => `${x.label}=${x.present ? x.raw || '(空)' : '(无此参数)'}`).join('　')}`);
    if (r.note) L.push(`      ${r.note}`);
  }
  L.push('  说明：DSC 每个节点有各自的 dm.ini，逐节点核对才能发现「某节点少一道控制」。');
  return L.join('\n');
}

/** HTML 段：给报告用（插进报告的一节）。 */
export function renderConsistencyHtml(c) {
  if (!c || c.labels.length < 2) return '';
  const head = `<table class="matrix"><thead><tr><th style="width:180px">项目</th>${c.labels
    .map((l) => `<th>${l}</th>`)
    .join('')}<th style="width:86px">一致性</th></tr></thead><tbody>`;
  const body = c.rows
    .map(
      (r) =>
        `<tr><td><span class="ctl">${r.key}</span><div class="note">${r.title}</div></td>` +
        r.cells
          .map(
            (x) =>
              `<td>${x.present ? (x.raw ? `<code>${x.raw}</code>` : '<span class="muted">(空)</span>') : '<span class="badge warn">无此参数</span>'}</td>`,
          )
          .join('') +
        `<td>${r.same ? '<span class="badge ok">一致</span>' : `<span class="badge ${r.level}">不一致</span>`}</td></tr>`,
    )
    .join('\n');
  const foot = `</tbody></table>`;
  const warn =
    c.divergent.length > 0
      ? `<div class="advice"><span class="advice-tag">需处理</span>发现 <b>${c.divergent.length} 项</b>节点间不一致：${c.divergent
          .map((r) => `${r.title}（${r.key}）`)
          .join('、')}。DSC 各节点有各自的 <code>dm.ini</code>，这类漂移会让「某节点少一道控制」而不被察觉。</div>`
      : `<div class="note">未发现节点间安全配置漂移（已比对 ${c.sameCount} 项）。</div>`;
  return `<div class="note">DSC 每个节点有各自的 <code>dm.ini</code>，<code>V$DM_INI</code> 按节点返回；本节逐项比对与安全判定相关的参数与版本事实。</div>${head}${body}${foot}${warn}`;
}

/** 节点覆盖度说明：调用方给了几个节点、实际连上几个、DSC 自称几个。 */
export function describeCoverage({ dscNodes, targets, connected, failedCount = 0 }) {
  const lines = [];
  const declared = dscNodes && dscNodes > 1 ? dscNodes : null;
  lines.push(
    `节点覆盖度：库内声明 ${declared ?? '—'} 个节点；本次目标 ${targets.length} 个（${targets.map((t) => t.label).join('、')}）；` +
      `实际连上 ${connected.length} 个${failedCount ? `，失败 ${failedCount} 个` : ''}。`,
  );
  if (declared && connected.length < declared) {
    lines.push(
      `⚠️ 只检查了 ${connected.length} / ${declared} 个节点 —— **未检查的节点上的配置漂移不会被发现**。` +
        '达梦的 `V$DSC_EP_INFO` 不含地址列，插件无法自动发现对端节点，必须由调用方通过 `targets` 给出。',
    );
  }
  return lines.join('\n');
}
