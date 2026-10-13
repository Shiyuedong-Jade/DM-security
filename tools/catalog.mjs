/**
 * 离线命令行工具（不需要 DSH、不连库）。
 *
 * 用法：
 *   node tools/catalog.mjs                              列出 60 项检查项目录
 *   node tools/catalog.mjs demo-report                  用内置演示数据生成一份 HTML 报告
 *   node tools/catalog.mjs demo-report <输出目录>
 *   node tools/catalog.mjs [catalog|demo-report] --level 2|3|4    切换等保对照级别（默认 3）
 *
 * 为什么要有它：没有装 DSH、或手边没有达梦环境时，也要能查阅评估口径、
 * 以及确认报告形态是否符合预期。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');

const load = (rel) => import(pathToFileURL(path.join(PKG, rel)).href);
const { CHECKS, DOMAINS } = await load('lib/checks.js');
const { ALL_QUERIES } = await load('lib/queries.js');
const { runChecks, buildMeta, rowsToObjects } = await load('lib/analyze.js');
const { buildReportHtml } = await load('lib/report.js');
const { collect, collectOs } = await load('lib/drivers/index.js');
const { COMPLIANCE_LEVELS, DEFAULT_COMPLIANCE_LEVEL, levelMeta, standardName, parseControl, minLevelOf } = await load('lib/compliance.js');

const cmd = process.argv[2] ?? 'catalog';
/** `--level N`：等保对照级别（第二 / 三 / 四级）。不合法就退回默认，并在输出里写明。 */
const levelFlag = (() => {
  const i = process.argv.indexOf('--level');
  if (i < 0 || !process.argv[i + 1]) return { level: DEFAULT_COMPLIANCE_LEVEL, explicit: false };
  const v = Number(process.argv[i + 1]);
  return COMPLIANCE_LEVELS.includes(v) ? { level: v, explicit: true } : { level: DEFAULT_COMPLIANCE_LEVEL, explicit: false, bad: process.argv[i + 1] };
})();
const LEVEL = levelFlag.level;
const LM = levelMeta(LEVEL);

if (cmd === 'catalog') {
  console.log(`达梦安全评估检查项目录：共 ${CHECKS.length} 项，分 ${DOMAINS.length} 个域。`);
  console.log(`等保对照级别：第 ${LEVEL} 级（${LM.label}）· ${standardName(LEVEL)}${levelFlag.bad ? `（--level ${levelFlag.bad} 非法，已退回默认）` : ''}\n`);
  for (const d of DOMAINS) {
    const items = CHECKS.filter((x) => x.domain === d.key);
    console.log(`【${d.order}. ${d.title}】${items.length} 项`);
    for (const it of items) {
      const pre = [
        it.edition === 'secure' ? '仅安全版' : null,
        it.priv === null ? '需 SSH' : it.priv !== 'SYSDBA' ? `需 ${it.priv}` : '需 SYSDBA',
      ]
        .filter(Boolean)
        .join(' / ');
      const ids = it.compliance ?? [];
      const ctl = ids.map((c) => parseControl(c, LEVEL)).filter(Boolean).map((p) => p.id);
      const minL = minLevelOf(ids);
      console.log(
        `  ${it.id.padEnd(24)} ${it.title}　[最重结论 ${it.level}｜${pre}｜等保 ${ctl.length ? ctl.join(' ') : '（加固项）'}]` +
          (minL > LEVEL ? `　← 第 ${minL} 级起要求，本级不适用` : ''),
      );
    }
    console.log('');
  }
  console.log(`采集查询 ${ALL_QUERIES.length} 条，全部为只读 SELECT。口径详见 DESIGN.md §2。`);
} else if (cmd === 'demo-report') {
  const outDir = path.resolve(process.argv[3] && !process.argv[3].startsWith('--') ? process.argv[3] : path.join(PKG, 'reports'));
  fs.mkdirSync(outDir, { recursive: true });
  const data = await collect({ driver: 'demo' }, ALL_QUERIES);
  // 演示报告也把**主机侧**跑起来（driver=demo 时 collectOs 用内置样例，不连任何机器），
  // 否则离线报告里那 7 项会全是「未启用 OS 访问」，演示价值减半
  const os = collectOs({ driver: 'demo', host: 'dsc-node1:7236' }, { dbPort: 7236, retentionDays: 180 });
  const result = runChecks(data, { complianceLevel: LEVEL, os });
  const meta = buildMeta(result.shape, {
    target: '(demo)',
    account: '（演示数据）',
    privSource: '内置演示数据',
    osAccess: `已启用（${os.detail}）`,
    versionEvidence: { sql: data.buildType?.sqlUsed ?? null, row: rowsToObjects(data.buildType).rows?.[0] ?? null },
  });
  const stamp = new Date().toISOString().slice(0, 19).replace('T', '-').replace(/:/g, '');
  const file = path.join(outDir, `dm-security-demo-L${LEVEL}-${stamp}.html`);
  fs.writeFileSync(
    file,
    buildReportHtml({
      meta,
      result,
      snapshots: data,
      generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
      driver: 'demo',
      disclaimer:
        '本报告由内置演示数据生成，**不对应任何真实数据库**，仅用于展示报告形态与判定分支。\n\n' +
        '真实评估请通过 DSH 工具 `dm_security_assess`（driver=jdbc）执行。',
    }),
    'utf8',
  );
  console.log(`演示报告已生成：${file}`);
  console.log(`等保对照级别：第 ${LEVEL} 级（${LM.label}）　因级别差异判「不适用」${result.naByLevel} 项`);
  console.log(`结论分布　严重 ${result.counts.crit}　警告 ${result.counts.warn}　合规 ${result.counts.ok}　提示 ${result.counts.info}　不适用 ${result.counts.na}　未取到 ${result.counts.unknown}　（已判定 ${result.assessed} 项；不给出评分）`);
} else {
  console.log('用法：node tools/catalog.mjs [catalog|demo-report] [输出目录] [--level 2|3|4]');
  process.exit(2);
}
