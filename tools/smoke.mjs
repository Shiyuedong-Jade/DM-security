/**
 * 达梦安全评估插件 —— 离线自检（不连库）。
 *
 * 用法：node tools/smoke.mjs
 *
 * 覆盖（对应 DESIGN §9 验收标准）：
 *   1. 插件契约形状（apply / inject / name / 工具定义 / 输出 schema）
 *   2. **只读断言**：所有 SQL 只以 SELECT / WITH 开头；桥有白名单；口令散列被丢弃
 *   3. 目录完整性：DESIGN.md §4 的检查项 ID 与 checks.js **完全一致**（防文档与代码漂移）
 *   4. demo 全流程：六态结论全部出现、na/unknown 都有非空原因、评分与合规矩阵成立
 *   5. 报告：单文件零外部依赖、不泄露口令散列
 *   6. 文本渲染可用
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');
/**
 * 交付物根 = 包根。
 *
 * ★ 2026-10-13 发布前调整：原先 `ROOT = PKG/..`（因为 `DESIGN.md` 当时放在插件目录**之外**），
 *   而 GitHub 的装法是 `dsh plugin add github:<user>/<repo>` —— **仓库根必须就是插件包**，
 *   所以 `DESIGN.md` 已移进包内，这里也随之改成 `ROOT = PKG`。
 */
const ROOT = PKG;

let failed = 0;
let passed = 0;
const ok = (c, m) => {
  if (c) passed++;
  else failed++;
  console.log((c ? '  [通过] ' : '  [失败] ') + m);
};

const read = (p) => fs.readFileSync(p, 'utf8');

/**
 * 依赖桩：`@deepseek-ai/dsh-tools` 是 **peerDependency**（由 DSH 宿主提供，不随包分发）。
 *
 * 为什么需要这一步：`lib/index.js` 在模块顶层 `import { defineTool } from '@deepseek-ai/dsh-tools'`，
 * 而没有 `node_modules` 的环境（CI、刚 clone、`npm pack` 后解包）里这个 import 会直接 ERR_MODULE_NOT_FOUND，
 * 于是**自检本身跑不起来**。这里只在「确实没装」时写一个最小桩（`defineTool = (t) => t`），
 * 让 `node tools/smoke.mjs` 在任何环境都能验证 195 项断言；装了真依赖时**完全不碰**。
 */
/** 本次是否用了桩：决定「编译后参数」那几条断言怎么验（见 §1 的说明）。 */
let DEP_STUBBED = false;
{
  const dep = path.join(PKG, 'node_modules', '@deepseek-ai', 'dsh-tools');
  if (!fs.existsSync(path.join(dep, 'package.json'))) {
    fs.mkdirSync(dep, { recursive: true });
    fs.writeFileSync(
      path.join(dep, 'package.json'),
      JSON.stringify({ name: '@deepseek-ai/dsh-tools', version: '0.0.0-stub', type: 'module', main: 'index.js' }, null, 2),
    );
    fs.writeFileSync(path.join(dep, 'index.js'), '// 自检用最小桩（仅缺依赖时生成）\nexport const defineTool = (t) => t;\n');
    DEP_STUBBED = true;
    console.log('  [信息] 未检测到 @deepseek-ai/dsh-tools，已写入最小桩（仅本次自检使用，node_modules 不入库）');
  }
}

// ============================================================ 0. 文件齐备
console.log('\n=== 0. 交付物齐备性 ===');
for (const f of [
  // 仓库根 = 包根（发布形态）：设计与说明文档都在包内
  'DESIGN.md',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'CHANGELOG.md',
  'package.json',
  'cordis.patch.yml',
  path.join('.github', 'workflows', 'ci.yml'),
  path.join('assets', 'java', 'DmQuery.java'),
  path.join('lib', 'index.js'),
  path.join('lib', 'checks.js'),
  path.join('lib', 'ossh.js'),
  path.join('lib', 'queries.js'),
  path.join('lib', 'analyze.js'),
  path.join('lib', 'report.js'),
  path.join('lib', 'bridge.js'),
  path.join('lib', 'compliance.js'),
  path.join('lib', 'drivers', 'demo.js'),
  path.join('tools', 'smoke.mjs'),
  path.join('tools', 'catalog.mjs'),
  path.join('tools', 'live-assess.mjs'),
  path.join('tools', 'plugin-e2e.mjs'),
]) {
  ok(fs.existsSync(path.join(ROOT, f)), `存在 ${f}`);
}

// ============================================================ 0b. 仓库卫生（发布前守卫）
console.log('\n=== 0b. 仓库卫生：真机凭据不得入库 ===');
{
  /**
   * 禁止出现的字符串。**用片段拼出来**，这样守卫自己的源码里也不会留下这些字面量
   * （否则它每次都会命中自己，然后被人注释掉 —— 这条守卫就废了）。
   */
  const BANNED = [
    ['DM', 'dba', '_123'].join(''), // 真机 sysdba 口令（演示数据里已换成 Demo#Passw0rd!）
    ['DM', '250718'].join(''), // 真机 SSH / 采集账号口令前缀
    ['10', '.127', '.11.'].join(''), // 内网地址段（已统一改为 10.0.0.x）
    ['aw', 'r1'].join(''), // 真机采集账号名（已统一改为 appuser）
  ];
  const SKIP = /node_modules|\.dm-home|dm-security-reports|[\\/]reports[\\/]|[\\/]\.git[\\/]/;
  const walk = (dir) =>
    fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
      const p = path.join(dir, e.name);
      if (SKIP.test(p)) return [];
      return e.isDirectory() ? walk(p) : [p];
    });
  const hits = [];
  for (const f of walk(PKG)) {
    if (!/\.(md|js|mjs|json|yml|yaml|sh|java|txt|xml)$/.test(f)) continue;
    const t = read(f);
    for (const b of BANNED) if (t.includes(b)) hits.push(`${path.relative(PKG, f)}（${b.slice(0, 4)}…）`);
  }
  ok(hits.length === 0, `包内不含真机口令 / 内网地址 / 采集账号名${hits.length ? ` —— 命中：${hits.join('、')}` : ''}`);
  ok(!fs.existsSync(path.join(PKG, 'dm-security-reports')), '真实评估报告目录不入库（.gitignore 已忽略）');
  ok(read(path.join(PKG, '.gitignore')).includes('*.jar'), '.gitignore 忽略达梦 JDBC 驱动（商业组件不得再分发）');
}

// ============================================================ 1. 插件契约
console.log('\n=== 1. 插件契约形状 ===');
let plugin = null;
try {
  plugin = await import(pathToFileURL(path.join(PKG, 'lib', 'index.js')).href);
  ok(true, 'lib/index.js 可加载');
} catch (e) {
  ok(false, `lib/index.js 加载失败：${e.message}`);
  console.log('  （若缺 @deepseek-ai/dsh-tools，请先安装 peerDependencies）');
}
if (plugin) {
  ok(typeof plugin.apply === 'function', 'apply 是函数');
  ok(Array.isArray(plugin.inject) && plugin.inject.includes('tools'), "inject 含 'tools'");
  ok(plugin.name === 'dm-security-assess', `插件名 = ${plugin.name}`);

  let registered = null;
  const ctx = { tools: { register: (t) => { registered = t; return () => {}; } }, get: () => undefined };
  plugin.apply(ctx, {});
  ok(registered !== null, 'apply() 调用了 ctx.tools.register()');
  ok(registered?.name === 'dm_security_assess', `工具名 = ${registered?.name}`);
  ok(typeof registered?.execute === 'function', '工具提供 execute');
  // defineTool 的编译产物不保留 isConcurrencySafe，所以按**源码**断言（同 09 组的做法）
  ok(/isConcurrencySafe:\s*\(\)\s*=>\s*true/.test(read(path.join(PKG, 'lib', 'index.js'))), '声明了并发安全（纯只读）');

  const p = registered?.parameters;
  const isRequired = (schema, name) =>
    Array.isArray(schema?.required) ? schema.required.includes(name) : schema?.properties?.[name]?.required === true;
  /**
   * ★ CI 抓到的坑（2026-10-13，第一次 push 后 run #1 失败）：
   *   这三条断言验的是**真实 `defineTool` 把参数 DSL 编译成 JSON Schema** 的产物，
   *   而干净检出/CI 里没有 `@deepseek-ai/dsh-tools`（peer，由宿主提供），用的是本文件上面的最小桩
   *   `defineTool = (t) => t` —— 桩不编译，于是这三条必红（本地装了依赖所以一直是绿的）。
   *   修法：装了真依赖 → 照旧验编译产物；只有桩 → 改为验**我们自己声明的 DSL 形状**
   *   （`action.required` / `action.enum` / `level.type` 都是我们写的，任何环境都该成立）。
   */
  if (DEP_STUBBED) {
    console.log('  [信息] 未安装 @deepseek-ai/dsh-tools（CI / 干净检出）：跳过「编译后参数」断言，改验声明的 DSL 形状');
    ok(p?.action?.required === true, 'DSL：action 声明为必填');
    ok(
      Array.isArray(p?.action?.enum) && p.action.enum.join() === 'assess,report,list',
      'DSL：action 允许 assess / report / list',
    );
    ok(p?.level?.type === 'integer', 'DSL：level 声明为 integer（等保对照级别）');
  } else {
    ok(p?.type === 'object', '编译后参数是 object');
    ok(isRequired(p, 'action'), 'action 为必填（编译后 required 数组含 action）');
    ok(
      Array.isArray(p?.properties?.action?.enum) && p.properties.action.enum.join() === 'assess,report,list',
      'action 允许 assess / report / list',
    );
  }
  const os = registered?.output?.schema;
  ok(os?.type === 'object' && os?.additionalProperties === false, '输出 schema 显式 object + additionalProperties: false');
  ok(['action', 'text'].every((k) => isRequired(os, k)), '输出 schema 核心字段 required（action / text）');
  // 回归守卫：**已取消评分**，输出里不允许再出现 score / grade
  // （2026-10-12 按用户要求取消：加权分会把「硬性不符合」与「加固建议」压成一个数字，
  //   改由 text 里的结论分布 + 逐项结论承载；见 DESIGN §2.2）
  ok(!('score' in (os?.properties ?? {})) && !('grade' in (os?.properties ?? {})), '输出 schema 不再含 score / grade（评分已取消）');
  ok(typeof registered?.output?.render === 'function', '提供 output.render');
}

// ============================================================ 2. 只读边界
console.log('\n=== 2. 只读边界 ===');
const { ALL_QUERIES, QUERY_PURPOSE } = await import(pathToFileURL(path.join(PKG, 'lib', 'queries.js')).href);
const WRITE_RE = /\b(UPDATE|INSERT|DELETE|ALTER|CREATE|DROP|GRANT|REVOKE|TRUNCATE|MERGE|COMMIT|ROLLBACK|EXEC|CALL)\b/i;

let allSqlReadOnly = true;
let writeHit = null;
for (const q of ALL_QUERIES) {
  for (const sql of [q.sql, ...(q.fallbacks ?? [])]) {
    const s = String(sql).replace(/^\uFEFF/, '').trim().toUpperCase();
    if (!s.startsWith('SELECT') && !s.startsWith('WITH')) {
      allSqlReadOnly = false;
      writeHit = `${q.key}: 不以 SELECT/WITH 开头`;
    }
    // 去掉字符串字面量后再查写关键字：`'SP_CREATE_JOB'` 这类常量名不算写语句
    const noStr = String(sql).replace(/'[^']*'/g, "''");
    const m = noStr.match(WRITE_RE);
    if (m) {
      allSqlReadOnly = false;
      writeHit = `${q.key}: 出现写关键字 ${m[1]}`;
    }
  }
}
ok(allSqlReadOnly, `全部 ${ALL_QUERIES.length} 条查询均为只读 SELECT/WITH${writeHit ? `（${writeHit}）` : ''}`);
ok(
  ALL_QUERIES.every((q) => typeof q.key === 'string' && q.key.length > 0),
  '每条查询都有 key',
);
const missingPurpose = ALL_QUERIES.filter((q) => !QUERY_PURPOSE[q.key]).map((q) => q.key);
ok(missingPurpose.length === 0, `每个查询都有用途说明（缺：${missingPurpose.join('、') || '无'}）`);

const bridgeSrc = read(path.join(PKG, 'assets', 'java', 'DmQuery.java'));
ok(/startsWith\("SELECT"\)\s*\|\|\s*s\.startsWith\("WITH"\)/.test(bridgeSrc), 'Java 桥只放行 SELECT / WITH');
ok(!/\bexecuteUpdate\b/.test(bridgeSrc), 'Java 桥不使用 executeUpdate（无写通道）');
// 数据卫生守卫：桥写下的 res-*.json 是**未经脱敏**的原始结果（脱敏在 analyze 层，晚于落盘），
// 所以成功路径必须删掉；失败路径保留并在错误信息里给出路径，便于排查。
const bridgeJs = read(path.join(PKG, 'lib', 'bridge.js'));
ok(/if \(ok\) \{[\s\S]{0,200}fs\.rmSync\(outFile/.test(bridgeJs), '桥在成功读取后删除原始结果文件（未脱敏数据不留盘）');
ok(/let ok = false/.test(bridgeJs) && /失败时保留/.test(bridgeJs), '桥的失败路径保留临时文件并给出路径（便于排查）');
const analyzeSrc = read(path.join(PKG, 'lib', 'analyze.js'));
ok(/SECRET_COL_RE/.test(analyzeSrc) && /PASSWORD/.test(analyzeSrc), '分析层有口令散列丢弃逻辑');
const indexSrc = read(path.join(PKG, 'lib', 'index.js'));
// 「不试默认口令、不为验证而变更」在实现层面的可验证形式有两条：
//   ① 执行路径不自己拼 SQL —— 一律经 collect() 走 queries.js 里的只读语句；
//   ② 只有驱动层能拿到执行入口。
// ⚠️ 不能用「文件里出现 FROM DBA_ 」来判：检查项的**修复建议与补齐办法**里
//    会（也应该）写给人工跑的命令，那是文档而不是可执行路径 —— 那样判会误伤大量正常文案。
ok(!/runSql\s*\(/.test(indexSrc), 'index.js 不直接调 runSql（SQL 只在 queries.js）');
const sqlCallers = ['index.js', 'checks.js', 'analyze.js', 'report.js', 'util.js', 'drivers/demo.js', 'drivers/index.js']
  .filter((f) => /import[^;]*\b(runQueries|runSql)\b/.test(read(path.join(PKG, 'lib', f))));
ok(sqlCallers.length === 1 && sqlCallers[0] === 'drivers/index.js',
  `只有驱动层能拿到执行入口（实际：${sqlCallers.join('、') || '无'}）`);

// 功能验证：redact 必须真的抹掉口令列
const { redact, rowsToObjects } = await import(pathToFileURL(path.join(PKG, 'lib', 'analyze.js')).href);
const leaked = redact([{ USERNAME: 'X', PASSWORD: 'SECRET_HASH_XYZ' }]);
ok(leaked[0].PASSWORD === '***', 'redact() 把 PASSWORD 列替换为 ***');
const zipped = rowsToObjects({ columns: ['USERNAME', 'PASSWORD'], rows: [['X', 'SECRET_HASH_XYZ']] });
ok(zipped.rows[0].PASSWORD === '***', 'rowsToObjects() 在数组形态下也抹掉口令散列');

// ============================================================ 3. 目录完整性
console.log('\n=== 3. 目录完整性（DESIGN ↔ 代码）===');
const { CHECKS, DOMAINS } = await import(pathToFileURL(path.join(PKG, 'lib', 'checks.js')).href);
const designText = read(path.join(ROOT, 'DESIGN.md'));
const designIds = new Set();
for (const m of designText.matchAll(/^\|\s*`([a-z][a-z0-9]*\.[a-z0-9_]+)`/gm)) designIds.add(m[1]);
const codeIds = new Set(CHECKS.map((c) => c.id));
const onlyDesign = [...designIds].filter((x) => !codeIds.has(x));
const onlyCode = [...codeIds].filter((x) => !designIds.has(x));
ok(designIds.size === codeIds.size && onlyDesign.length === 0 && onlyCode.length === 0,
  `DESIGN 与代码检查项 ID 完全一致（DESIGN ${designIds.size} 项 / 代码 ${codeIds.size} 项）` +
    (onlyDesign.length ? `；仅 DESIGN 有：${onlyDesign.join('、')}` : '') +
    (onlyCode.length ? `；仅代码有：${onlyCode.join('、')}` : ''));
ok(codeIds.size === CHECKS.length, '检查项 ID 无重复');
ok(new RegExp(`共 ${CHECKS.length} 项|${CHECKS.length} 项`).test(designText), `DESIGN 中的项数与代码一致（${CHECKS.length}）`);

const domainKeys = new Set(DOMAINS.map((d) => d.key));
const badDomain = CHECKS.filter((c) => !domainKeys.has(c.domain)).map((c) => c.id);
ok(badDomain.length === 0, `所有检查项的域都有效（越界：${badDomain.join('、') || '无'}）`);
const badLevel = CHECKS.filter((c) => !['crit', 'warn', 'info'].includes(c.level)).map((c) => c.id);
ok(badLevel.length === 0, `所有检查项声明了合法的最重结论（越界：${badLevel.join('、') || '无'}）`);
// 等保映射：要么给控制点，要么显式声明为「加固项」（不映射条款）——不允许两者都缺
const noCompliance = CHECKS.filter((c) => !(c.compliance ?? []).length && !c.hardening).map((c) => c.id);
ok(noCompliance.length === 0, `所有检查项都有等保映射或显式标为加固项（缺：${noCompliance.join('、') || '无'}）`);
const hardening = CHECKS.filter((c) => c.hardening).map((c) => c.id);
ok(hardening.length > 0, `有 ${hardening.length} 项标为加固项（不映射等保条款）：${hardening.join('、')}`);
const queryKeys = new Set(ALL_QUERIES.map((q) => q.key));
const badNeeds = [];
for (const c of CHECKS) for (const k of c.needs ?? []) if (!queryKeys.has(k)) badNeeds.push(`${c.id}→${k}`);
ok(badNeeds.length === 0, `所有 needs 都指向真实查询（越界：${badNeeds.join('、') || '无'}）`);
const noJudge = CHECKS.filter((c) => typeof c.judge !== 'function').map((c) => c.id);
ok(noJudge.length === 0, `所有检查项都有 judge（缺：${noJudge.join('、') || '无'}）`);
ok(
  DOMAINS.length === 13 && DOMAINS.every((d, i) => d.order === i + 1),
  '13 个域、order 连续',
);

// ============================================================ 4. demo 全流程
console.log('\n=== 4. demo 全流程（不连库）===');
const { runDemoQueries } = await import(pathToFileURL(path.join(PKG, 'lib', 'drivers', 'demo.js')).href);
const { collect } = await import(pathToFileURL(path.join(PKG, 'lib', 'drivers', 'index.js')).href);
const { runChecks, LEVELS, buildMeta, judgeConformity, conformityCounts } = await import(pathToFileURL(path.join(PKG, 'lib', 'analyze.js')).href);
const { buildReportHtml, renderText } = await import(pathToFileURL(path.join(PKG, 'lib', 'report.js')).href);

const data = await collect({ driver: 'demo' }, ALL_QUERIES);
ok(Object.keys(data).length === ALL_QUERIES.length, `demo 覆盖全部 ${ALL_QUERIES.length} 条查询`);
// 演示数据里**只允许出现刻意构造的**失败：profiles 权限不足（复现受限账号采集）。
// 其它任何 error 都说明 demo 与 ALL_QUERIES 脱节了。
const intendedErrors = ['profiles'];
const errKeys = Object.entries(data).filter(([, v]) => v.error).map(([k]) => k);
ok(
  errKeys.length === intendedErrors.length && errKeys.every((k) => intendedErrors.includes(k)),
  `demo 的失败查询只有刻意构造的 ${intendedErrors.join('、')}（实际：${errKeys.join('、') || '无'}）`,
);
const missingKeys = ALL_QUERIES.filter((q) => !(q.key in data)).map((q) => q.key);
ok(missingKeys.length === 0, `demo 覆盖了全部查询 key（缺：${missingKeys.join('、') || '无'}）`);
ok(!JSON.stringify(data).includes('DEMO_NO_DATA'), 'demo 没有 DEMO_NO_DATA（说明每个 key 都有样例数据）');

const result = runChecks(data, {});
const present = LEVELS.filter((lv) => result.results.some((r) => r.level === lv));
ok(present.length === LEVELS.length, `六态结论全部出现（实测：${present.join('、')}）`);
ok(result.results.length === CHECKS.length, `产出 ${result.results.length} 条结论，与检查项数一致`);

const bareNa = result.results.filter((r) => (r.level === 'na' || r.level === 'unknown') && !String(r.message).trim());
ok(bareNa.length === 0, `不适用/未取到均有非空原因（裸判：${bareNa.map((r) => r.id).join('、') || '无'}）`);
// ★ 已取消评分：结果对象里不应再出现 score / grade，只有结论分布与已判定项数
ok(result.score === undefined && result.grade === undefined, '结果里没有 score / grade（评分已取消）');
ok(result.counts.crit > 0 && result.counts.warn > 0, `结论分布合理（严重 ${result.counts.crit} / 警告 ${result.counts.warn}）`);
ok(result.compliance.length > 0, `等保映射矩阵非空（${result.compliance.length} 个控制点）`);
ok(result.compliance.every((c) => c.title && c.requirement), '等保映射每行都带章条标题与要求摘要');
// 条款级符合性（等保测评口径）——把逐项六态归纳成「这条要求满足没有」
ok(result.compliance.every((c) => c.conformity?.key && c.conformity?.reason), '每个控制点都带条款级符合性与判定依据');
{
  const mk = (levels) => levels.map((lv, i) => ({ id: `t${i}`, level: lv }));
  const cases = [
    [['crit', 'ok'], 'fail', '不符合'],
    [['warn', 'ok'], 'partial', '部分符合'],
    [['ok', 'ok'], 'pass', '符合'],
    [['ok', 'unknown'], 'partial', '部分符合'],
    [['unknown', 'unknown'], 'pending', '无法判定'],
    [['na', 'na'], 'na', '不适用'],
    [['info'], 'pending', '无法判定'],
  ];
  const bad = cases.filter(([ls, key, label]) => {
    const r = judgeConformity(mk(ls));
    return r.key !== key || r.label !== label;
  });
  ok(bad.length === 0, `条款级符合性 7 条分支全部命中${bad.length ? `（偏差：${bad.map(([ls]) => ls.join('+')).join('，')}）` : ''}`);
  ok(judgeConformity(mk(['ok', 'unknown'])).reason.includes('证据不全'), '「合规 + 未取到」不给「符合」，理由写明证据不全');
  ok(judgeConformity(mk(['info'])).reason.includes('不构成'), '只有「提示」不给「符合」，并说明提示不构成合规证据');
}
{
  const cc = conformityCounts(result.compliance);
  const sum = Object.values(cc).reduce((a, b) => a + b, 0);
  ok(sum === result.compliance.length, `符合性分布合计等于条款数（${sum} = ${result.compliance.length}）`);
}
ok(result.hardeningItems.length > 0, `加固项被单独归类（${result.hardeningItems.length} 项，不映射等保条款）`);
ok(result.openItems.length > 0, `未闭环清单非空（${result.openItems.length} 项）`);
ok(result.shape.cluster === '单实例' && result.shape.version === 'DM Database Server x64 V8', `形态识别正确（${result.shape.cluster} / ${result.shape.version}）`);
ok(result.shape.secure === false, '样例被正确判为无安全版能力');
// 版本与实例信息（取法对齐 02 组「基础信息」：版本类型与内核版本号由 ID_CODE 解出）
ok(result.shape.edition === '企业版' && result.shape.innerVersion === '8.1.5.60', `版本信息取自 ID_CODE（${result.shape.edition} / 内核 ${result.shape.innerVersion}）`);
ok(result.shape.license?.daysLeft === 45 && result.shape.license?.state === 'warn', '授权剩余天数与提醒状态正确（45 天 → warn）');
ok(result.shape.charset?.pageSizeBytes != null && result.shape.startTime != null, '建库参数与启动时间已取到');
ok(result.assessed === result.results.filter((r) => ['crit', 'warn', 'ok'].includes(r.level)).length, '已判定项 = 严重+警告+合规');

// ★ 呈现约定（2026-10-12 按用户反馈加）：多项内容走 `items` 列表，不塞进一句话。
//   起因：真机报告里「PROFILE 有 8 项 UNLIMITED」被渲染成一大串逗号，读者要自己数、自己断句。
const withItems = result.results.filter((r) => Array.isArray(r.items) && r.items.length);
ok(withItems.length > 0, `有 ${withItems.length} 项用列表（items）呈现多项内容：${withItems.map((r) => r.id).join('、')}`);
const badItems = result.results.filter(
  (r) => r.items !== undefined && (!Array.isArray(r.items) || r.items.some((t) => typeof t !== 'string' || !t.trim())),
);
ok(badItems.length === 0, `items 均为非空字符串数组（问题项：${badItems.map((r) => r.id).join('、') || '无'}）`);
const tooLongNoList = result.results.filter((r) => String(r.message).length > 300 && !(r.items?.length));
ok(
  tooLongNoList.length === 0,
  `没有「结论超长且未用列表」的项（${tooLongNoList.map((r) => `${r.id}:${r.message.length}`).join('、') || '无'}）`,
);

// 判定分支回归锚点：这些结论若被改坏，必须在这里暴露。
// 锚点里既有「真机校准过的默认值不算缺陷」（dba_admin_option=ok、public_obj_privs 系统属主），
// 也有「真机纠正后从 unknown 变成可判定」（reuse_limit=warn、ip_whitelist=ok），
// 以及受限账号采集时的「未取到」（profile 系列）。
const byId = Object.fromEntries(result.results.map((r) => [r.id, r]));
const anchors = [
  ['audit.enable', 'crit'],
  ['dac.dba_holders', 'crit'],
  ['dac.user_admin_privs', 'crit'],
  ['ident.locked_expired', 'crit'],
  ['ident.dormant_accounts', 'warn'],
  ['comm.enable_encrypt', 'warn'],
  ['net.session_sources', 'warn'],
  ['expo.dangerous_exec', 'warn'],
  ['expo.public_synonyms', 'warn'],
  ['pwd.reuse_limit', 'warn'],
  ['pwd.never_expire', 'warn'],
  ['dac.public_obj_privs', 'warn'],
  ['auth.ip_whitelist', 'ok'],
  ['auth.remote_osauth', 'ok'],
  ['dac.dba_admin_option', 'ok'],
  ['dac.public_sys_privs', 'ok'],
  ['pwd.lock_threshold', 'ok'],
  ['res.max_sessions', 'ok'],
  ['mac.edition', 'na'],
  ['mac.policy_objects', 'na'],
  ['sod.priv_flag', 'na'],
  ['audit.realtime', 'na'],
  ['res.profile_inventory', 'unknown'],
  ['res.cpu_limit', 'unknown'],
  ['res.mem_limit', 'unknown'],
  ['res.session_limit', 'unknown'],
  ['pwd.lock_time', 'unknown'],
  ['pwd.idle_timeout', 'unknown'],
  ['res.unlimited_admins', 'info'],
];
const anchorBad = anchors.filter(([id, lv]) => byId[id]?.level !== lv).map(([id, lv]) => `${id}=${byId[id]?.level}(期望 ${lv})`);
ok(anchorBad.length === 0, `${anchors.length} 个判定锚点全部命中${anchorBad.length ? `；偏差：${anchorBad.join('，')}` : ''}`);

// ============================================================ 5. 报告
console.log('\n=== 5. 报告 ===');
// meta 一律用插件导出的 buildMeta 构造（手拼会漏字段 —— 曾经把版本/授权显示成「未取到」）
const meta = buildMeta(result.shape, {
  target: 'demo',
  account: '（demo）',
  privSource: '内置演示数据',
  // 版本取值证据也照生产路径带上（报告里会渲染成可展开的 SQL + 原始行）
  versionEvidence: { sql: data.buildType?.sqlUsed ?? null, row: rowsToObjects(data.buildType).rows?.[0] ?? null },
});
const html = buildReportHtml({
  meta,
  result,
  snapshots: data,
  generatedAt: '2026-10-12 09:23:43',
  disclaimer: '只读评估说明。',
  driver: 'demo',
});
ok(html.startsWith('<!DOCTYPE html>') && html.includes('</html>'), 'HTML 结构完整');
ok(!/<script/i.test(html), '报告不含任何 <script>');
ok(!/https?:\/\//i.test(html) && !/cdn/i.test(html), '报告零外部依赖（无 CDN / 无外链）');
ok(html.includes('等保 2.0 三级控制点对照') && html.includes('未闭环清单'), '报告含等保对照与未闭环清单两节');
ok(!/评分|得分/.test(html), '报告里不出现「评分/得分」（已取消评分）');
ok(html.includes('采集账号') && html.includes('权限层判定'), '报告头部显示采集账号与权限层判定');
ok(html.includes('要求（摘要）'), '等保对照表带「要求」列');
// 目录 / 锚点完整性：目录里每个 href 都要有对应的 id（防断链），且实现里**没有脚本**
{
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
  const hrefs = [...html.matchAll(/href="#([^"]+)"/g)].map((m) => m[1]);
  const broken = [...new Set(hrefs.filter((x) => !ids.has(x)))];
  ok(html.includes('class="toccard"') && hrefs.length >= 20, `报告含两级目录（${hrefs.length} 个跳转条目）`);
  ok(broken.length === 0, `目录锚点全部指向存在的 id（断链：${broken.join('、') || '无'}）`);
  ok((html.match(/class="totop"/g) || []).length >= 6, '每个章节标题都带「↑ 目录」回跳');
  ok(html.includes(':target{') && html.includes('scroll-behavior:smooth'), '锚点跳转有平滑滚动与目标高亮（纯 CSS，无脚本）');
  ok(html.includes('id="d-ident"') && /id="c-8_1_4_1"/.test(html), '目录子条目锚点覆盖分域与等保章条');
}
// 报告是 HTML，不是 Markdown：直接拼进 HTML 的说明文字里若带 `**粗体**`，页面上会原样显示星号。
// 这个缺陷只在截图里看得出来（自检不看渲染结果），所以用断言兜住。
{
  const leaks = [...html.matchAll(/\*\*[^*\n]{1,60}\*\*/g)].map((m) => m[0]);
  ok(leaks.length === 0, `报告 HTML 里不残留 Markdown 粗体标记（残留：${[...new Set(leaks)].join('、') || '无'}）`);
}
// 条款级符合性：表里有「符合性」列 + 看板 + 判法说明（用户直接问的就是「这条要求满足没有」）
ok(html.includes('>符合性<') && /class="confchip (pass|partial|fail|na|pending)"/.test(html), '等保对照表带「符合性」列与条款级 chip');
ok(html.includes('符合性是怎么判的') && html.includes('不构成合规证据'), '报告写明符合性的判定规则（含「提示不构成证据」）');
ok(/本轮共对照 <b>\d+<\/b> 条/.test(html), '报告给出条款级符合性看板（合计条数）');
ok(/<code>[a-z]+\.[a-z_]+<\/code><span class="mini (crit|warn|ok|info|na|unknown)">/.test(html), '涉及检查项后标注该单项结论（看得出是哪一项拉低了符合性）');
ok(html.includes('版本与实例信息') && html.includes('内核版本号') && html.includes('授权有效期'), '报告含版本与实例信息块（内核版本号 / 授权有效期）');
// 回归守卫：构建号与 ID_CODE 是同一串时**不能并列占两行**（用户反馈的重复问题）
ok(html.includes('构建 / ID_CODE') && html.includes('ID_CODE 为同一串'), '构建号与 ID_CODE 等价时合并为一行（不重复展示）');
// 版本号必须可复核：把判定版本用的原始 SQL 与取值一并给出
ok(html.includes('INNER_VERSION') && html.includes('class="sql"'), '报告含版本号取值证据（原始 SQL + 原始行）');
ok(html.includes('内置演示数据'), 'demo 报告带有「演示数据」显著提示');
for (const lv of LEVELS) ok(html.includes(`badge ${lv}`), `报告渲染了 ${lv} 态的样式`);

// 口令泄露负向测试：把口令散列塞进采集结果，确认报告里不出现
const tainted = { ...data, users: { columns: ['USERNAME', 'PASSWORD'], rows: [['X', 'SECRET_HASH_XYZ']] } };
const taintedResult = runChecks(tainted, {});
const taintedHtml = buildReportHtml({ meta, result: taintedResult, snapshots: { users: { columns: [], rows: [{ USERNAME: 'X', PASSWORD: 'SECRET_HASH_XYZ' }] } }, generatedAt: 'T', disclaimer: 'd' });
ok(!taintedHtml.includes('SECRET_HASH_XYZ'), '报告里不出现口令散列明文');
ok(/<ul class="items">/.test(html), 'HTML 报告把 items 渲染为 <ul class="items">');
ok(!/<li>[^<]{0,3}<\/li>/.test(html), '列表项不为空（渲染时未丢内容）');

const text = renderText(result, meta);
ok(text.includes('结论分布') && text.includes('分域明细') && text.includes('未闭环'), '文本渲染含结论分布/分域/未闭环');
ok(text.includes('采集账号'), '文本结论里写明了采集账号');
// 回归守卫：meta 由 buildMeta 统一构造，不能在验证脚本里手拼（曾因此把版本/授权显示成「未取到」）
ok(!/版本信息：类型 未取到/.test(text), '文本的版本信息不是「未取到」（meta 字段完整）');
ok(/授权：到期 \d{4}-\d{2}-\d{2}/.test(text), '文本写出授权到期日与剩余天数');
ok(text.includes('等保 2.0 三级控制点对照') && text.includes('要求：'), '文本结论含等保要求摘要');
ok(/条款级符合性：符合 \d+/.test(text) && text.includes('依据：'), '文本结论给出条款级符合性分布与逐条依据');
ok(/^ {6}· /m.test(text), '文本结论把 items 渲染为缩进条目（    · ……）');
ok(text.length > 500, `文本结论长度合理（${text.length} 字符）`);

// 文本渲染也应覆盖 na 的说明，避免「静默不适用」
ok(/不适用/.test(text), '文本结论明确写出「不适用」');

// ============================================================ 5b. 等保对照级别（level=2/3/4）
console.log('\n=== 5b. 等保对照级别（第二 / 三 / 四级）===');
const cmp = await import(pathToFileURL(path.join(PKG, 'lib', 'compliance.js')).href);
ok(cmp.normalizeLevel(2) === 2 && cmp.normalizeLevel(4) === 4 && cmp.normalizeLevel(9) === 3, 'normalizeLevel 把非法值收敛到默认第三级');
ok(
  cmp.parseControl('8.1.4.2(d)', 2).id === '7.1.4.2(d)' &&
    cmp.parseControl('8.1.4.2(d)', 3).id === '8.1.4.2(d)' &&
    cmp.parseControl('8.1.4.2(d)', 4).id === '9.1.4.2(d)',
  '条款编号按级别重写（7.1.4.x / 8.1.4.x / 9.1.4.x）',
);
ok(
  cmp.parseControl('8.1.4.1(d)', 2).applicable === false &&
    cmp.parseControl('8.1.4.2(g)', 2).applicable === false &&
    cmp.parseControl('8.1.4.2(a)', 2).applicable === true &&
    cmp.parseControl('8.1.4.2(d)', 2).applicable === true,
  'minLevel 决定本级是否适用（身份鉴别 d 双因素 / 访问控制 g 安全标记三级起；访问控制 a、d 二级即有）',
);
ok(cmp.minLevelOf(['8.1.4.2(a)']) === 2 && cmp.minLevelOf(['8.1.4.4(c)']) === 3 && cmp.minLevelOf([]) === 1, 'minLevelOf：条款最低适用级别 / 加固项为 1');
ok(cmp.minLevelOf(['8.1.4.1(c)', '8.1.4.8(a)']) === 2, '一项映射多条条款时取最低级别（有二级条款就不整项排除）');
ok(cmp.parseControl('9.1.4.2(g)', 2)?.id === '7.1.4.2(g)', 'parseControl 也接受其他级别编号（按目标级别重写）');
ok(/第二级/.test(cmp.standardName(2)) && /9\.1\.4\.x/.test(cmp.standardName(4)), 'standardName 随级别给出标准名与章条号');
ok(cmp.controlTable(['8.1.4.4(c)'], 2)[0]?.minLevel === 3 && cmp.controlTable(['8.1.4.4(c)'], 2)[0]?.applicable === false, 'controlTable 带适用级别信息');
ok(cmp.levelBasis(2).notes.length > 0 && cmp.levelBasis(4).notes.some((n) => /强制访问控制/.test(n)), 'levelBasis 给出各级口径说明');
ok(cmp.parseControl('8.1.4.99(a)', 3) === null && cmp.parseControl('乱七八糟', 3) === null, '表中没有的条款号返回 null（不产出假编号）');
ok(cmp.parseControl('8.1.4.2(z)', 3)?.requirement === null, '表内未知字母不伪造要求文本（requirement 为 null）');

/** 三级相对二级的增量，落在插件用到的 6 个检查项上 */
/**
 * 三级相对二级的增量，落在插件用到的 8 个检查项上：
 *   库内 6 项（8.1.4.4(c) 三项 + 8.1.4.2(g) 两项 + 8.1.4.4(e) 一项）
 * + 主机侧 2 项（目录/配置文件权限映射到 8.1.4.2(f)「客体到文件级」，该条款三级才出现）。
 * 主机侧那两项即便配了 SSH、真拿到了「其他用户可写」，二级对照下也判「不适用（级别差异）」——
 * 这是**忠于标准条款**的结果：二级「安全计算环境」没有文件级粒度的独立条款；
 * 但技术结论照样保留在 items 里，风险不会被藏起来。
 */
const LADDER_IDS = [
  'auth.ip_whitelist',
  'auth.login_window',
  'net.session_sources',
  'mac.edition',
  'mac.policy_objects',
  'expo.version_patch',
  'os.dm_home_perms',
  'os.config_file_perms',
];
const r2 = runChecks(data, { complianceLevel: 2 });
const r4 = runChecks(data, { complianceLevel: 4 });
ok(result.complianceLevel === 3 && result.naByLevel === 0, '默认按第三级对照：没有因级别差异判「不适用」的项');
ok(r2.complianceLevel === 2 && r2.naByLevel === LADDER_IDS.length, `level=2：${LADDER_IDS.length} 项三级专属条款判「不适用」（实测 ${r2.naByLevel}）`);
const belowIds = r2.results.filter((r) => r.levelApplicability === 'below-level').map((r) => r.id).sort();
ok(belowIds.join(',') === [...LADDER_IDS].sort().join(','), `级别差异项定位正确：${belowIds.join('、')}`);
ok(
  r2.results
    .filter((r) => r.levelApplicability === 'below-level')
    .every((r) => (r.items ?? []).length >= 2 && r.originalLevel && r.minLevel === 3),
  '不适用项保留技术结论与原始级别（na ≠ 已合规）',
);
ok(
  r2.results.filter((r) => r.levelApplicability === 'below-level').every((r) => String(r.message).length > 0),
  '级别差异导致的不适用也带非空原因（不出现裸判）',
);
ok(r4.complianceLevel === 4 && r4.naByLevel === 0, 'level=4：没有因级别差异判「不适用」的项');
ok(r4.results.filter((r) => (r.compliance ?? []).length).every((r) => r.complianceLevel === 4), '每条结论都记录本次对照级别');
const m2 = r2.compliance;
ok(m2.length > 0 && m2.every((c) => /^7\.1\.4\./.test(c.control)), 'level=2 的控制点矩阵编号全部为 7.1.4.x');
ok(m2.some((c) => c.notApplicableByLevel), 'level=2 的矩阵标出「本级不适用」的控制点');
ok(
  r2.counts.crit + r2.counts.warn + r2.counts.ok <= result.counts.crit + result.counts.warn + result.counts.ok,
  '降低对照级别只会把项移出不适用（判定分母只减不增）',
);

const html2 = buildReportHtml({ meta, result: r2, snapshots: data, generatedAt: 'T2', disclaimer: 'd' });
ok(html2.includes('等保 2.0 二级控制点对照') && html2.includes('<span class="ctl">7.1.4.4(c)</span>'), '报告按 level=2 渲染标题与条款编号');
ok(!/<span class="ctl">8\.1\.4\./.test(html2), '报告 level=2 时控制点 chip 不再出现三级编号');
ok(html2.includes('第 3 级起要求') && html2.includes('适用级别') && html2.includes('级别差异'), '报告标注高等级专属项、「适用级别」列与级别差异说明');
const text2 = renderText(r2, meta);
ok(text2.includes('等保对照：第 2 级（第二级）') && text2.includes('技术结论（按第 3 级口径）'), '文本结论写出对照级别并保留三级口径的技术结论');
const text4 = renderText(r4, meta);
ok(text4.includes('等保对照：第 4 级（第四级）') && text4.includes('9.1.4.'), '文本结论按 level=4 给出 9.1.4.x 编号');

// ============================================================ 5c. 主机侧（OS / SSH，P2）
console.log('\n=== 5c. 主机侧：命令白名单 / 掩码 / 三态降级 ===');
const osMod = await import(pathToFileURL(path.join(PKG, 'lib', 'ossh.js')).href);
const { collectOs } = await import(pathToFileURL(path.join(PKG, 'lib', 'drivers', 'index.js')).href);
const threw = (fn) => {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
};

// ① 白名单：7 条命令都能通过形态校验，且没有任何写动词 / 重定向
const osCmdArgs = { perms: [['/a/b', '/c']], audit: ['/d'], plaintext: ['/e'], history: ['/f'] };
const osCmds = Object.entries(osMod.OS_PROBE).map(([k, v]) => [k, v.build(...(osCmdArgs[k] ?? []))]);
ok(osCmds.length === 7, `主机侧命令共 7 条（实测 ${osCmds.length}）`);
ok(osCmds.every(([, c]) => Object.values(osMod.OS_PROBE).some((x) => x.shape.test(c))), '7 条命令都通过形态白名单（执行前再验一遍）');
ok(
  osCmds.every(([, c]) => {
    // `2>/dev/null` 是**故意**的（丢掉 ss/netstat 缺失的报错噪声），它不是写操作；
    // 先把它摘掉再看还有没有写动词与重定向。
    const bare = c.replace(/2>\/dev\/null/g, '');
    return !/\b(rm|mv|cp|chmod|chown|mkdir|touch|kill|systemctl|service|shutdown|reboot|dd|tee)\b|>>?\s*\//.test(bare);
  }),
  '7 条命令里没有写动词、也没有重定向（只读断言；`2>/dev/null` 除外）',
);
ok(threw(() => osMod.runRemote({ command: 'rm -rf /', host: 'h', user: 'u', password: 'p' })), '非白名单形态的命令被拒绝（纵深防御）');
ok(threw(() => osMod.OS_PROBE.perms.build(['/a;rm -rf /'])), '路径参数里的注入字符被拦（抛错，不静默清洗）');

// ② 掩码：口令不得离开本模块
const maskedOs = osMod.maskSecrets('disql SYSDBA/Demo#Passw0rd!@10.0.0.1:5236 password=hunter2');
ok(!maskedOs.includes('Demo#Passw0rd!') && !maskedOs.includes('hunter2') && maskedOs.includes('SYSDBA/***@'), '连接串与 password= 都被掩码');
ok(
  osMod.parseHistoryHits('12:disql SYSDBA/Demo#Passw0rd!@h:5236').every((h) => !h.snippet.includes('Demo#Passw0rd!')),
  '历史命中片段在解析时就已掩码',
);
ok(osMod.parseHistoryHits('12:disql SYSDBA/***@h:5236').length === 0, '已掩码文本不会被重复计为命中（幂等）');
// 真机误报回归守卫（2026-10-12，DMDSC 10.0.0.61）：DM 自带 client-cert.pem 的
// `CN=DEVELOP/dmeng@dameng.com` 曾命中宽模式，报出 10 处假「明文口令」。
ok(
  osMod.parseHistoryHits('Subject: C=cn, O=dameng, CN=DEVELOP/dmeng@dameng.com').length === 0 &&
    osMod.parsePlaintextHits('11:Issuer: C=cn, OU=developer, CN=fhx/dmeng@demeng.com').length === 0,
  '证书的 Subject / Issuer 行不算明文口令命中（真机误报回归守卫）',
);
ok(osMod.parsePlaintextHits('/x/start.sh:12:disql SYSDBA/abc123@h:5236 -e 1').length === 1, '脚本里的真实连接串仍然命中');
// 同批真机误报的另两类（2026-10-12）：XPath 表达式与驱动源码里的模板串
ok(
  osMod.parsePlaintextHits('95:    <xsl:for-each select="/testsuites/testcase/@package = $name]">').length === 0 &&
    osMod.parsePlaintextHits("123:                conn_string = '%s/%s@%s' % (user, passwd, mpp_type, host)").length === 0,
  'XPath 表达式与源码模板串都不算明文口令（真机误报回归守卫）',
);

// 真机路径形态回归（2026-10-12，DMDSC 10.0.0.61）：
// DSC 的 dm.ini 在 `<DM_HOME>/data/DSC01/DSC01_conf/` 下，比单实例多一层 —— 早先按
// `<DM_HOME>/data/<实例>/dm.ini` 硬套会推出错误的 DM_HOME，于是去扫一个不存在的目录（谎报合规）。
const dscProc = osMod.parseProc(
  'dmdba 4096 /home/dmdba/dmdbms/bin/dmserver dcr_ini=/home/dmdba/dmdbms/data/DSC01/dmdcr.ini /home/dmdba/dmdbms/data/DSC01/DSC01_conf/dm.ini',
)[0];
ok(dscProc?.cmd === '/home/dmdba/dmdbms/bin/dmserver', 'parseProc 取到可执行文件路径');
ok(osMod.deriveDmHome(dscProc) === '/home/dmdba/dmdbms', 'DSC：从 /bin/dmserver 推出 DM_HOME（真机校准）');
const dscPaths = osMod.derivePaths(dscProc);
ok(
  dscPaths.includes('/home/dmdba/dmdbms/data/DSC01/DSC01_conf/dm.ini') && dscPaths.includes('/home/dmdba/dmdbms/data/DSC01/DSC01_conf/audit'),
  'DSC：dm.ini 与审计目录按真实层级推导（多一层 DSC01_conf）',
);
ok(dscPaths.includes('/home/dmdba/dmdbms/data') && dscPaths.includes('/home/dmdba/dmdbms'), 'DSC：数据目录与安装目录都进核对清单');
ok(/^(.*)\/data\/DAMENG\/dm\.ini$/.test('/home/dmdba/dmdbms/data/DAMENG/dm.ini'), '单实例布局仍被兼容（data/DAMENG/dm.ini）');

// ③ 解析器（真机形态的样例行）
const procLine = 'dmdba 4321 /home/dmdba/dmdbms/bin/dmserver /home/dmdba/dmdbms/data/DAMENG/dm.ini -noconsole';
ok(osMod.parseProc(procLine)[0]?.user === 'dmdba', 'parseProc 取到运行账号');
ok(osMod.parseProc(procLine)[0]?.iniPath === '/home/dmdba/dmdbms/data/DAMENG/dm.ini', 'parseProc 取到 dm.ini 路径');
ok(osMod.parseStat('750 dmdba:dinstall /home/dmdba/dmdbms')[0]?.mode === '750', 'parseStat 取到权限与属主');
ok(osMod.parseListen('LISTEN 0 128 0.0.0.0:7236 0.0.0.0:*')[0]?.port === 7236, 'parseListen 取到监听地址与端口');
ok(osMod.parseSshd('PermitRootLogin no').permitrootlogin === 'no', 'parseSshd 解析 sshd_config 的键值行');
ok(osMod.parseAuditFiles('2024-06-30 2048 /a/audit/x.aud').length === 1, 'parseAuditFiles 解析审计文件清单');
ok(
  osMod.judgeAuditRetention([{ date: '2026-10-01', path: 'x', size: 1 }], 180, new Date('2026-10-12T00:00:00Z')).state === 'short',
  '保留期判定：11 天 < 180 天 → short（早期记录已被滚掉）',
);
ok(
  osMod.judgeAuditRetention([{ date: '2020-01-01', path: 'x', size: 1 }], 180, new Date('2026-10-12T00:00:00Z')).state === 'ok',
  '保留期判定：远超 180 天 → ok',
);

// ④ 三态之一：未配 SSH → na（并说明怎么开）
const osNa = result.results.filter((r) => r.domain === 'os');
ok(osNa.length === 7 && osNa.every((r) => r.level === 'na' && /sshUser/.test(r.message)), '未配 SSH：主机侧 7 项判「不适用」并说明怎么开');
ok(osNa.every((r) => r.priv === null), '主机侧项声明 priv=null（走 SSH，不要求库权限）');

// ⑤ 演示两套场景（离线覆盖「合规」与「严重」两条路）
const osGood = collectOs({ driver: 'demo', host: 'dsc-node1:7236' }, { dbPort: 7236, retentionDays: 180 });
const osBad = collectOs({ driver: 'demo', host: 'dsc-node2:7237' }, { dbPort: 7237, retentionDays: 180 });
const lvOf = (res) => Object.fromEntries(res.results.filter((r) => r.domain === 'os').map((r) => [r.id, r.level]));
const resGood = runChecks(data, { os: osGood });
const resBad = runChecks(data, { os: osBad });
const gGood = lvOf(resGood);
const gBad = lvOf(resBad);
ok(Object.values(gGood).every((lv) => lv === 'ok' || lv === 'info'), '规范场景：主机侧无警告与严重');
ok(gBad['os.run_user'] === 'crit' && gBad['os.dm_home_perms'] === 'crit', '做坏场景：root 运行 + 目录 other 可写判「严重」');
ok(gBad['os.listen_binding'] === 'warn' && gBad['os.plaintext_credential'] === 'warn', '做坏场景：监听全网卡 + 明文口令判「警告」');
ok(gBad['os.audit_retention'] === 'warn', '做坏场景：审计目录为空判「警告」');
ok(!JSON.stringify(resBad).includes('Demo#Passw0rd!'), '主机侧结论对象里不出现口令明文（掩码在源头生效）');
ok(gGood['os.sshd_baseline'] === 'info', '只允许口令认证 → 判「提示」而不是警告（避免天天误报）');
// 真机清理后才暴露的分支（2026-10-13）：`grep` 找不到命中 → 退出码 1、输出为空。
// 这与「命令没跑」在输出上完全一样，必须靠退出码区分，否则把「扫了但干净」误报成「未取到」。
ok(gGood['os.plaintext_credential'] === 'ok', '明文口令扫描「跑完但没命中」→ 判「合规」（不是「未取到」）');
const osNoScan = { ...osGood, facts: { ...osGood.facts, exit: { ...osGood.facts.exit, history: 127, plaintext: 127 } } };
ok(lvOf(runChecks(data, { os: osNoScan }))['os.plaintext_credential'] === 'unknown', '扫描命令没跑起来（exit=127）→ 才判「未取到」');
ok(/200/.test(osMod.OS_PROBE.history.build('/home/x')), '历史扫描上限放宽到 200（真机上 41 条曾被 tail -20 低报成 20）');

// ⑥ 三态之二/之三：SSH 失败分支（注入假的 run：不需要真机，也不做任何真实登录尝试）
const fakeRun = (stderr) => () => ({ ok: false, status: 1, stdout: '', stderr, error: null });
const denied = osMod.probeOs({ ssh: { host: 'h', user: 'u', password: 'p' }, run: fakeRun('Access denied') });
ok(denied.state === 'unknown' && /Access denied/.test(denied.detail), '口令错 / 被拒 → 主机侧判「未取到」并带 plink 原文');
const keyTrouble = osMod.probeOs({ ssh: { host: 'h', user: 'u', password: 'p' }, run: fakeRun('The server host key is not cached') });
ok(/sshHostKey/.test(keyTrouble.detail), '主机密钥未确认 → 明确提示用 sshHostKey 传指纹');
ok(denied.commands.length === 1, 'SSH 连不上时立即停止（只试 1 条命令，不让 7 个 plink 超时叠起来）');
const resUnknown = runChecks(data, { os: denied });
ok(
  resUnknown.results.filter((r) => r.domain === 'os').every((r) => r.level === 'unknown' && /Access denied/.test(r.message)),
  'SSH 失败时主机侧 7 项判「未取到」（绝不谎报成没问题）',
);

// ⑥b 主机密钥**不能被空白切分**（真机实测 2026-10-14，`10.0.0.40`）
//
// `sshConfigOf` 原来对**所有**逐节点参数都用同一个 `/[\s,;]+/` 切分。而 SSH 主机密钥指纹
// 本身含空格（`ssh-ed25519 255 SHA256:…`）—— 于是一个指纹被拆成三段，调用方取 `list[0]`
// 正好拿到 `ssh-ed25519`，plink 报
//   `'ssh-ed25519' is not a valid format for a manual host key specification`
// 主机侧 7 项全部落成「未取到」，而报告只说"SSH 连接失败"，看不出根因是切分切坏的。
// 而那个带空格的格式，**正是本插件参数说明与提示文案让用户填的那个**。
// 真机另验：Node 把完整字符串原样交给 plink 时两种格式都收 —— 问题只在这一处切分。
// 指纹用**构造值**（不进真机公钥）—— 这一条测的是"空格不被切坏"，与具体指纹无关。
const FP_ED = 'ssh-ed25519 255 SHA256:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK';
const FP_BARE = 'SHA256:LLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVV';
const utilMod = await import(pathToFileURL(path.join(PKG, 'lib', 'util.js')).href);
ok(utilMod.splitNodeList(FP_ED).length === 3, 'splitNodeList 默认按空白切 —— 正是它会把一个指纹拆成三段（主机密钥因此不能走默认）');
ok(
  utilMod.splitNodeList(FP_ED, { byWhitespace: false }).length === 1 &&
    utilMod.splitNodeList(FP_ED, { byWhitespace: false })[0] === FP_ED,
  '★ splitNodeList 关闭空白切分后，带空格的指纹**原样**是一个值',
);
const sshOne = plugin.sshConfigOf({
  args: { sshUser: 'root', sshPassword: 'p', sshHostKey: FP_ED },
  cfg: {},
  targets: [{ label: 'a', host: '10.0.0.1' }],
});
ok(sshOne.nodes[0].hostKey === FP_ED, '★ sshConfigOf：单节点时主机密钥**完整保留**（修复前会变成 "ssh-ed25519"）');
const sshMulti = plugin.sshConfigOf({
  args: { sshUser: 'root', sshPassword: 'p', sshHost: '10.0.0.1,10.0.0.2', sshHostKey: `${FP_ED},${FP_BARE}` },
  cfg: {},
  targets: [{ label: 'a', host: '10.0.0.1' }, { label: 'b', host: '10.0.0.2' }],
});
ok(
  sshMulti.nodes.length === 2 && sshMulti.nodes[0].hostKey === FP_ED && sshMulti.nodes[1].hostKey === FP_BARE,
  '★ sshConfigOf：多节点主机密钥用**逗号**分隔并逐节点保留（DMDSC 上两节点指纹本就不同）',
);
ok(
  sshMulti.nodes[0].host === '10.0.0.1' && sshMulti.nodes[1].host === '10.0.0.2',
  '主机名仍按逗号/空格拆分（只有主机密钥改了口径，既有行为不变）',
);
ok(
  plugin
    .sshConfigOf({ args: { sshUser: 'u', sshPassword: 'p', sshHostKey: FP_ED }, cfg: {}, targets: [{ label: 'a', host: 'h1' }, { label: 'b', host: 'h2' }] })
    .nodes.every((n) => n.hostKey === FP_ED),
  '只给一个指纹时所有节点都用它（既有行为不变）',
);

// ⑦ 报告里主机侧的呈现
const htmlOs = buildReportHtml({
  meta: { ...meta, osAccess: '已启用（只读白名单命令）' },
  result: resGood,
  snapshots: data,
  generatedAt: 'T3',
  disclaimer: 'd',
});
ok(htmlOs.includes('主机侧（OS / SSH）') && htmlOs.includes('OS 访问'), '报告含主机侧分域与「OS 访问」行');
ok(htmlOs.includes('走 SSH，不要求库权限') && htmlOs.includes('主机侧只读命令'), '主机侧项标出「走 SSH」与命令依据');

// ============================================================ 6. DSC 多节点（离线）
console.log('\n=== 6. DMDSC 多节点与节点间一致性（离线）===');
const { normalizeAll } = await import(pathToFileURL(path.join(PKG, 'lib', 'analyze.js')).href);
const dsc = await import(pathToFileURL(path.join(PKG, 'lib', 'dsc.js')).href);

// demo 驱动按 host 造场景：含 dsc → 双节点形态；结尾 2 → 第二节点（审计已开、本地 OS 认证已关）
const nodes = [];
for (const h of ['dsc-node1:7236', 'dsc-node2:7237']) {
  const raw = await collect({ driver: 'demo', host: h }, ALL_QUERIES);
  const d = normalizeAll(raw);
  nodes.push({ label: h, data: d, shape: runChecks(d, {}).shape });
}
ok(nodes[0].shape.cluster === 'DMDSC 共享存储集群', `DSC 形态识别（${nodes[0].shape.cluster}）`);
ok(nodes[0].shape.epNames.length === 2, `从 V$DSC_EP_INFO 取到节点名：${nodes[0].shape.epNames.join('、')}`);

const cons = dsc.judgeNodeConsistency(nodes);
ok(cons.divergent.length === 2, `检出 ${cons.divergent.length} 项节点间不一致（期望 2）`);
const divKeys = cons.divergent.map((r) => r.key).sort().join(',');
ok(divKeys === 'ENABLE_AUDIT,ENABLE_LOCAL_OSAUTH', `不一致项定位正确：${divKeys}`);
ok(cons.divergent.every((r) => r.level === 'crit'), '安全开关类的节点间不一致判为「严重」');
ok(cons.sameCount > 5, `同时确认了 ${cons.sameCount} 项一致（不是只报差异）`);
const ctext = dsc.renderConsistencyText(cons);
const chtml = dsc.renderConsistencyHtml(cons);
ok(ctext.includes('不一致') && ctext.includes('严重'), '一致性文本含不一致项与严重标记');
ok(/<table/.test(chtml) && chtml.includes('不一致'), '一致性 HTML 渲染为节点对照表');
ok(
  /只检查了 1 \/ 2 个节点/.test(dsc.describeCoverage({ dscNodes: 2, targets: [{ label: 'a' }], connected: ['a'] })),
  '节点覆盖度不足时给出明确警告（未检查的节点漂移不会被发现）',
);

// ============================================================ 7. peer 范围（离线）
console.log('\n=== 7. 宿主依赖声明（离线）===');
// 预发布版本的放行规则很容易写错（`*` 连一个预发布都不匹配），这里把关键语义锁住。
// registry 上是否又发了新元组，由 tools/peer-range.mjs 联网查，不进本自检。
{
  const pr = await import(pathToFileURL(path.join(HERE, 'peer-range.mjs')).href);
  ok(pr.selfTest(true), `semver 子集语义自证（${pr.SEMVER_CASES.length} 条用例）`);
  const pkgJson = JSON.parse(fs.readFileSync(path.join(PKG, 'package.json'), 'utf8'));
  const tools = pkgJson.peerDependencies?.['@deepseek-ai/dsh-tools'] ?? '';
  const cordis = pkgJson.peerDependencies?.['@deepseek-ai/cordis'] ?? '';
  ok(!pkgJson.dependencies || Object.keys(pkgJson.dependencies).length === 0, '官方 @deepseek-ai/* 不放在 dependencies（宿主提供）');
  ok(pr.satisfies('0.1.5-rc.2', tools), 'peer 范围放行本机宿主在跑的 dsh-tools 0.1.5-rc.2');
  ok(pr.satisfies('0.1.7-rc.2', tools), 'peer 范围放行当前线 0.1.7-rc.2（枚举 0.1.x 各元组的目的）');
  ok(pr.satisfies('0.1.0-rc.6', tools), 'peer 范围放行社区文档点名的反例 0.1.0-rc.6');
  ok(!pr.satisfies('0.2.0-rc.2', tools), 'peer 范围不谎称支持 0.2 线（没测过就不声明）');
  ok(!pr.satisfies('0.1.7-rc.2', '^0.1.5-rc.2'), '反例：单分支写法够不到 0.1.7（说明为什么要枚举）');
  ok(pr.satisfies('4.0.2', cordis) && pr.satisfies('4.0.1-rc.1', cordis), 'cordis 范围覆盖稳定版与同线预发布');
}

// ============================================================ 8. 文档语气（离线）
console.log('\n=== 8. 文档语气自检（离线）===');
const tone = await import(pathToFileURL(path.join(HERE, 'doc-tone.mjs')).href);
const toneHits = tone.scanDocs();
const mechHits = toneHits.filter((h) => tone.PATTERNS.find((p) => p.key === h.key)?.mechanical);
ok(mechHits.length === 0, `零容忍语气痕迹为 0 处（破折号 / 翻案句 / 起手式 / 提示语冒号 / emoji / 徽章）`);
if (mechHits.length) for (const h of mechHits) console.log(`      ${h.file}:${h.line} [${h.label}] ${h.text}`);

// ============================================================ 汇总
console.log(`\n=== 自检汇总：通过 ${passed} 项，失败 ${failed} 项 ===`);
if (failed > 0) {
  console.log('存在失败项，请修复后重跑。');
  process.exit(1);
}
console.log('全部通过。离线自检完成（未连接任何数据库）。');
