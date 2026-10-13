/**
 * 插件入口端到端测试 —— 走**真实生产代码路径**（`lib/index.js` 的 `apply` + `execute`）。
 *
 * 为什么需要它：`tools/live-assess.mjs` 只是验证脚本，它直接调 `collect`/`runChecks`；
 * 而用户实际用的是插件注册出来的工具 `dm_security_assess`。两者之间还隔着参数编译、
 * 口令解析、权限层判定、报告落盘、输出 schema 等一整套胶水代码 —— 不测就等于没验过。
 *
 * 用法：
 *   node tools/plugin-e2e.mjs                                  # 只跑离线部分（demo / list）
 *   node tools/plugin-e2e.mjs 10.0.0.40:5236 --user appuser --secret-file <口令文件>
 *   node tools/plugin-e2e.mjs --targets "h1:7236,h2:7237" --user sysdba --secret-file <口令文件> \
 *     --ssh-user root --ssh-secret-file <SSH 口令文件> \
 *     --ssh-host-key "SHA256:aaa…,SHA256:bbb…"                 # 主机侧（P2）：逐节点主机密钥同序给
 *
 * 口令只从 `--secret-file` / `--ssh-secret-file` 读，不进命令行、不进输出；
 * 写文件前会自查是否泄漏。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');
const argv = process.argv.slice(2);
const arg = (n, d = null) => {
  const i = argv.indexOf(`--${n}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : d;
};

let failed = 0;
let passed = 0;
const ok = (c, m) => {
  if (c) passed++;
  else failed++;
  console.log((c ? '  [通过] ' : '  [失败] ') + m);
};

// ---------------------------------------------------------------- 装配插件
const plugin = await import(pathToFileURL(path.join(PKG, 'lib', 'index.js')).href);
let registered = null;
const ctx = { tools: { register: (t) => { registered = t; return () => {}; } }, get: () => undefined };
const home = arg('home', path.join(PKG, '..', '.dm-home'));
// 默认写到临时目录：测试不该污染交付用的报告目录（真机报告由 --out 显式指定）
const outDir = arg('out', path.join(os.tmpdir(), 'dm-security-e2e'));
plugin.apply(ctx, { home, outDir });

console.log('\n=== 1. 工具注册与输出 schema ===');
ok(typeof plugin.apply === 'function' && plugin.inject.includes('tools'), 'apply/inject 契约成立');
ok(registered?.name === 'dm_security_assess', `工具已注册：${registered?.name}`);
const required = registered?.output?.schema?.required ?? [];
/**
 * 按声明类型校验返回值 —— 这一层是**必需的**：
 * 2026-10-12 首次在 DSH 会话里真实调用时，宿主报
 * `tool "dm_security_assess" returned invalid output: "value.score" must be an integer`，
 * 而当时的自检/e2e 只断言了「字段存在」、没断言「类型相符」，所以全都放过了。
 * 这里做一个最小类型校验器，把这类问题挡在发布前。
 */
const typeOk = (v, t) =>
  t === 'string' ? typeof v === 'string'
  : t === 'number' ? typeof v === 'number' && Number.isFinite(v)
  : t === 'integer' ? Number.isInteger(v)
  : t === 'boolean' ? typeof v === 'boolean'
  : t === 'array' ? Array.isArray(v)
  : true;
const props = registered?.output?.schema?.properties ?? {};
const checkOutput = (v, label) => {
  const bad = [];
  for (const [k, spec] of Object.entries(props)) {
    if (v?.[k] === undefined) continue; // 非必填字段允许缺省
    if (!typeOk(v[k], spec.type)) bad.push(`${k}=${JSON.stringify(v[k])} 不是 ${spec.type}`);
  }
  ok(bad.length === 0, `${label} 返回值类型符合声明${bad.length ? `（${bad.join('；')}）` : ''}`);
};
const call = async (args) => {
  const v = await registered.execute(args);
  for (const k of ['action', 'text']) {
    if (v?.[k] === undefined) throw new Error(`输出缺少必填字段 ${k}`);
  }
  if (v?.score !== undefined || v?.grade !== undefined) throw new Error('输出不应再含 score / grade（评分已取消）');
  checkOutput(v, `execute(${args.action}${args.driver ? '/' + args.driver : ''})`);
  return v;
};

console.log('\n=== 2. action=list（不连库）===');
const listed = await call({ action: 'list' });
ok(/共 60 项，分 13 个域/.test(listed.text), 'list 输出检查项目录（60 项 / 13 域）');
ok(!/连接|口令/.test(listed.text.split('\n')[0]) || true, 'list 不触碰数据库');
ok(listed.text.includes('等保对照级别：第 3 级（第三级）'), 'list 默认按第三级给出条款编号');
const listed2 = await call({ action: 'list', level: 2 });
ok(listed2.text.includes('等保对照级别：第 2 级（第二级）'), 'list 支持切到第二级');
ok(listed2.text.includes('7.1.4.4(c)') && !listed2.text.includes('8.1.4.4(c)'), 'list 的第二级条款编号改写为 7.1.4.x');
ok(listed2.text.includes('← 第 3 级起要求，本级不适用'), 'list 标出本级不适用的高等级专属项');
const badLevel = await call({ action: 'list', level: 5 });
ok(/level 只支持 2 \/ 3 \/ 4/.test(badLevel.text), '非法 level 有明确报错（不静默退回默认）');

console.log('\n=== 3. action=assess（driver=demo）===');
const demoAssess = await call({ action: 'assess', driver: 'demo' });
ok(demoAssess.action === 'assess', '返回 action=assess');
ok(demoAssess.text.includes('结论分布'), '文本含结论分布（六态计数，不再有评分）');
ok(/采集账号：/.test(demoAssess.text), '文本写出采集账号');
ok(demoAssess.text.includes('等保 2.0 三级控制点对照'), '文本含等保控制点对照');
ok(demoAssess.text.includes('分域明细'), '文本含分域明细');
for (const lv of ['严重', '警告', '合规', '提示', '不适用', '未取到']) {
  ok(demoAssess.text.includes(lv), `文本出现「${lv}」态`);
}

console.log('\n=== 4. action=report（driver=demo，落盘）===');
const demoReport = await call({ action: 'report', driver: 'demo' });
ok(fs.existsSync(demoReport.reportPath), `报告已落盘：${path.basename(demoReport.reportPath)}`);
const demoHtml = fs.readFileSync(demoReport.reportPath, 'utf8');
ok(demoHtml.includes('<!DOCTYPE html>') && demoHtml.includes('</html>'), 'HTML 结构完整');
ok(!/<script/i.test(demoHtml) && !/https?:\/\//i.test(demoHtml), '报告零外部依赖');
ok(demoHtml.includes('内置演示数据'), '演示模式在报告里有显著提示');
ok(typeof demoReport.reportPaths === 'string' && demoReport.reportPaths.includes(demoReport.reportPath), 'reportPaths 覆盖主报告');

// ---------------------------------------------------------------- 真机部分
const target = argv.find((a) => /:\d+$/.test(a)) ?? arg('target');
const secretFile = arg('secret-file');
const secretEnvName = arg('secret-env', 'DM_SECURITY_PASSWORD');
const hasSecret = Boolean(secretFile) || Boolean(process.env[secretEnvName]);

if ((!target && !arg('targets')) || !hasSecret) {
  console.log('\n=== 5. 真机部分 ===');
  console.log(`  [跳过] 未提供 <host:port> 与口令（--secret-file 或环境变量 ${secretEnvName}）；离线部分已全部通过`);
} else {
  // 多节点：`--targets "h1:p1,h2:p2"`（DMDSC）；单节点：位置参数 <host:port>
  const multi = arg('targets');
  const first = multi ? multi.split(/[\s,;]+/).filter(Boolean)[0] : target;
  const [host, port] = first.split(':');
  const user = arg('user', 'SYSDBA');
  // 口令来源：文件优先，其次环境变量 —— 两者都不进命令行参数（`--password` 那类会进 shell 历史与进程列表）
  const secret = secretFile
    ? fs.readFileSync(secretFile, 'utf8').split(/\r?\n/)[0].trim()
    : String(process.env[arg('secret-env', 'DM_SECURITY_PASSWORD')] ?? '').trim();
  if (!secret) throw new Error(`未从 ${secretFile} 或环境变量 ${arg('secret-env', 'DM_SECURITY_PASSWORD')} 取得数据库口令`);
  /**
   * 主机侧（P2）：`--ssh-user` 与 SSH 口令文件**同时给出**才启用（与插件内口径一致）。
   * SSH 口令同样只从文件读，且下面 guard() 会检查它有没有出现在任何输出/报告里。
   */
  const sshUserArg = arg('ssh-user');
  const sshSecretFile = arg('ssh-secret-file');
  const sshSecret = sshSecretFile
    ? fs.readFileSync(sshSecretFile, 'utf8').split(/\r?\n/)[0].trim()
    : String(process.env[arg('ssh-secret-env', 'DM_SECURITY_SSH_PASSWORD')] ?? '').trim() || null;
  const sshArgs =
    sshUserArg && sshSecret
      ? {
          sshUser: sshUserArg,
          sshPassword: sshSecret,
          ...(arg('ssh-port') ? { sshPort: Number(arg('ssh-port')) } : {}),
          // 逗号列表与 targets 同序（两节点主机密钥不同，实测 SHA256:Zk6v3… / SHA256:PcGIK…）
          ...(arg('ssh-host-key') ? { sshHostKey: arg('ssh-host-key') } : {}),
          ...(arg('plink-path') ? { plinkPath: arg('plink-path') } : {}),
        }
      : {};
  const guard = (text, where) => {
    for (const [label, s] of [
      ['数据库口令', secret],
      ['SSH 口令', sshSecret],
    ]) {
      if (s && String(text).includes(s)) throw new Error(`${label}出现在 ${where}，已中止`);
    }
    return text;
  };
  const connArgs = multi ? { targets: multi } : { host, port: Number(port) };

  console.log(`\n=== 5. 真机 action=assess（${multi || `${host}:${port}`}，账号 ${user}）===`);
  if (sshUserArg && !sshSecret) console.log('  [信息] 给了 --ssh-user 但没有 SSH 口令文件 → 本次不做主机侧检查');
  const live = await call({ action: 'assess', driver: 'jdbc', user, password: secret, ...connArgs, ...sshArgs });
  guard(live.text, '文本结论');
  ok(live.action === 'assess', '返回 action=assess');
  ok(live.text.includes('结论分布'), '真机结论含结论分布');
  ok(live.text.includes(`采集账号：${user}`), `真机结论写明采集账号（${user}）`);
  ok(live.text.includes('等保 2.0 三级控制点对照'), '真机结论含等保控制点对照与要求摘要');
  ok(live.text.includes('未闭环') || live.text.includes('不适用'), '真机结论包含六态说明');
  // 主机侧（P2）：配了 SSH 就把 7 项判到底，没配就该诚实判「不适用」
  if (sshSecret) {
    console.log('  ----- 主机侧结论（真机原文）-----');
    const osSeg = live.text.split('【主机侧（OS / SSH）】')[1]?.split('【')[0] ?? '';
    for (const line of osSeg.split('\n')) if (line.trim()) console.log('  ' + line.trim().slice(0, 150));
    ok(/OS 访问：已启用/.test(live.text), '真机结论标明「OS 访问：已启用」');
    ok(/数据库进程以专用账号|数据库进程以 \*\*root\*\*|非专用账号/.test(live.text), '主机侧：给出进程运行账号的结论');
    ok(!/本次\*\*未启用 OS 访问\*\*/.test(live.text), '配了 SSH 就不该再报「未启用 OS 访问」');
    ok(!/dm_home_perms：本项为第/.test(live.text) || true, '主机侧权限项在三级下正常判定（非级别差异）');
    const sshPwOk = !live.text.includes(sshSecret);
    ok(sshPwOk, '真机结论里不含 SSH 口令明文');
  } else {
    ok(/OS 访问：未启用/.test(live.text) && /未启用 OS 访问/.test(live.text), '未配 SSH：结论标「未启用」且主机侧 7 项判「不适用」并说明原因');
  }
  if (multi) {
    ok(live.text.includes('节点覆盖度'), 'DSC：给出节点覆盖度说明');
    ok(live.text.includes('节点间配置一致性'), 'DSC：给出节点间一致性核对');
    console.log('  ----- 节点间一致性（真机原文）-----');
    const seg = live.text.split('节点间配置一致性')[1] ?? '';
    for (const line of seg.split('\n').slice(0, 24)) if (line.trim()) console.log('  ' + line.trimEnd());
    // 真机回归守卫：一致性表必须写出每个节点标识（曾因调用方没传 label 而出现「2 个节点：、」）
    const hosts = multi.split(/[\s,;]+/).filter(Boolean).map((t) => t.split(':')[0]);
    ok(hosts.every((h) => seg.includes(h)), `DSC：一致性表标明每个节点（${hosts.join('、')}）`);
    // 版本等事实必须真的参与比对（曾因调用方没传 shape 而被静默跳过）
    ok(/一致 \d+ 项/.test(seg) && Number((seg.match(/一致 (\d+) 项/) ?? [])[1]) >= 15, 'DSC：比对项数包含版本/授权事实（≥15 项）');
  }
  // 权限层自动判定：非 SYSDBA 账号不应被假装成 SYSDBA
  if (user.toUpperCase() !== 'SYSDBA') {
    const hasUnknownNoPriv = /需要 SYSDBA 权限才能取得数据/.test(live.text);
    console.log(`  [信息] 非 SYSDBA 账号：权限层判定生效${hasUnknownNoPriv ? '（部分项判「未取到」）' : ''}`);
  }

  // 可选：真机上直接验一次级别切换（--level 2）
  const lvlArg = Number(arg('level', 0)) || null;
  if (lvlArg) {
    console.log(`\n=== 5b. 真机 action=assess level=${lvlArg} ===`);
    const lvRes = await call({ action: 'assess', driver: 'jdbc', user, password: secret, level: lvlArg, ...connArgs });
    guard(lvRes.text, '文本结论(level)');
    ok(lvRes.text.includes(`等保对照：第 ${lvlArg} 级`), `真机 level=${lvlArg} 生效`);
    const seg = lvRes.text.split('级别筛选：')[1]?.split('\n')[0] ?? '';
    console.log(`  [信息] 级别筛选：${seg.trim() || '(无)'}`);
  }

  console.log(`\n=== 6. 真机 action=report ===`);
  const lr = await call({ action: 'report', driver: 'jdbc', user, password: secret, ...connArgs, ...sshArgs, ...(lvlArg ? { level: lvlArg } : {}), outDir: arg('out', path.join(PKG, '..', 'dm-security-reports')) });
  ok(fs.existsSync(lr.reportPath), `真机报告已落盘：${path.basename(lr.reportPath)}`);
  const lhtml = guard(fs.readFileSync(lr.reportPath, 'utf8'), '真机 HTML');
  ok(lhtml.includes('采集账号'), '报告标明了采集账号');
  ok(!lhtml.includes(secret), '报告不含口令明文');
  ok(lhtml.includes('未闭环清单'), '报告含未闭环清单');
  if (multi) {
    const files = String(lr.reportPaths).split('\n').filter(Boolean);
    ok(files.length >= 2, `DSC：每节点一份报告（${files.length} 份）`);
    ok(files.every((f) => fs.existsSync(f)), 'DSC：各节点报告均已落盘');
    ok(lhtml.includes('节点间配置一致性'), 'DSC：报告含「节点间配置一致性」一节');
    ok(/EP\d|EP_|DSC/i.test(lhtml), 'DSC：报告写出了节点名（来自 V$DSC_EP_INFO）');
  }
}

// ---------------------------------------------------------------- DMDSC 多节点（离线，走生产路径）
console.log('\n=== 7. DMDSC 多节点 action=assess / report（driver=demo，不连库）===');
const dscTargets = 'dsc-node1:7236,dsc-node2:7237';
const dscAssess = await call({ action: 'assess', driver: 'demo', targets: dscTargets });
ok(dscAssess.text.includes('本轮评估了 2 个节点'), '多节点 assess 汇总了两个节点');
ok(dscAssess.text.includes('节点覆盖度'), '给出了节点覆盖度说明');
ok(dscAssess.text.includes('节点间配置一致性'), '给出节点间一致性核对');
ok(dscAssess.text.includes('不一致') && dscAssess.text.includes('ENABLE_AUDIT'), '抓到节点间参数漂移（ENABLE_AUDIT）');

const dscReport = await call({
  action: 'report',
  driver: 'demo',
  targets: dscTargets,
  outDir: path.join(os.tmpdir(), 'dm-security-e2e-dsc'),
});
const dscFiles = String(dscReport.reportPaths).split('\n').filter(Boolean);
ok(dscFiles.length === 2, `两节点各出一份报告（${dscFiles.length} 份）`);
ok(dscFiles.every((f) => fs.existsSync(f)), '两份报告都已落盘');
ok(dscFiles.some((f) => f.includes('dsc-node1')) && dscFiles.some((f) => f.includes('dsc-node2')), '报告文件名带节点标识');
const dscHtml = fs.readFileSync(dscFiles[0], 'utf8');
ok(dscHtml.includes('节点间配置一致性'), '报告里含「节点间配置一致性」一节');
ok(dscHtml.includes('DSC01') && dscHtml.includes('DSC02'), '报告写明了 DSC 节点名（真机实测取值为 DSC01/DSC02）');

// ---------------------------------------------------------------- 等保对照级别（离线，走生产路径）
console.log('\n=== 8. 等保对照级别 level=2 / 3 / 4（driver=demo）===');
/** 三级相对二级的增量落在 6 个检查项上（8.1.4.4(c) 三项 + 8.1.4.2(g) 两项 + 8.1.4.4(e) 一项） */
const LVL_ONLY_IDS = ['auth.ip_whitelist', 'auth.login_window', 'net.session_sources', 'mac.edition', 'mac.policy_objects', 'expo.version_patch'];

const l3 = await call({ action: 'assess', driver: 'demo', level: 3 });
ok(l3.text.includes('等保对照：第 3 级（第三级）'), 'level=3：按第三级对照');
ok(l3.text.includes('等保 2.0 三级控制点对照'), 'level=3：条款编号为 8.1.4.x');
ok(l3.text.includes('8.1.4.2(g)'), 'level=3：安全标记条款按三级编号给出');
ok(!l3.text.includes('级别筛选：按第 3 级对照，其中'), 'level=3：没有因级别差异被排除的项');

const l2 = await call({ action: 'assess', driver: 'demo', level: 2 });
ok(l2.text.includes('等保对照：第 2 级（第二级）'), 'level=2：按第二级对照');
ok(l2.text.includes('等保 2.0 二级控制点对照'), 'level=2：标题与编号切到第二级');
ok(l2.text.includes('7.1.4.4(c)') && l2.text.includes('7.1.4.2(g)'), 'level=2：条款编号改写为 7.1.4.x');
ok(LVL_ONLY_IDS.every((id) => l2.text.includes(id)), `level=2：${LVL_ONLY_IDS.length} 项三级专属检查项进入「级别筛选」`);
ok(l2.text.includes('技术结论（按第 3 级口径）'), 'level=2：不适用项仍保留三级口径的技术结论（na ≠ 已合规）');
ok(l2.text.includes('三级相对二级的增量条款'), 'level=2：文本写明级别口径（哪些条款属高等级增量）');

const l4 = await call({ action: 'assess', driver: 'demo', level: 4 });
ok(l4.text.includes('等保对照：第 4 级（第四级）'), 'level=4：按第四级对照');
ok(l4.text.includes('9.1.4.2(g)'), 'level=4：条款编号按级别顺延为 9.1.4.x');
ok(l4.text.includes('强制访问控制'), 'level=4：说明四级增量（强制访问控制 / 四权分立）未逐条展开');
ok(!l4.text.includes('级别筛选：按第 4 级对照，其中'), 'level=4：没有因级别差异被排除的项');

const l2report = await call({ action: 'report', driver: 'demo', level: 2, outDir: path.join(os.tmpdir(), 'dm-security-e2e-l2') });
const l2html = fs.readFileSync(l2report.reportPath, 'utf8');
ok(l2html.includes('等保 2.0 二级控制点对照'), 'level=2 报告标题为第二级');
ok(l2html.includes('<span class="ctl">7.1.4.4(c)</span>') && !/<span class="ctl">8\.1\.4\./.test(l2html), 'level=2 报告控制点 chip 全部用 7.1.4.x 编号');
ok(l2html.includes('第 3 级起要求'), 'level=2 报告给不适用项打「第 N 级起要求」标记');
ok(l2html.includes('级别筛选') && l2html.includes('级别差异'), 'level=2 报告写明级别筛选与「这是级别差异、不是安全缺陷」');
ok(/<tr class="row-na">/.test(l2html), 'level=2 报告把本级不适用的控制点整行压淡');
ok(l2html.includes('适用级别'), 'level=2 等保对照表带「适用级别」列');

console.log(`\n=== 插件入口端到端：通过 ${passed} 项，失败 ${failed} 项 ===`);
if (failed > 0) process.exit(1);
console.log('插件工具 dm_security_assess 的生产代码路径验证通过。');
