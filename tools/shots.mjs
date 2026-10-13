/**
 * 生成 README / 插件市场用的报告截图（开发者工具，不连库、不需要 DSH）。
 *
 * 由来：`screenshots.json` 里的图是二进制，靠手工截图会随报告改版悄悄过期，
 * 而且没人知道当初是怎么截的。这里把过程写成脚本：先生成演示报告，
 * 再逐节截图，图与报告形态永远对得上。
 *
 * 为什么不是「打开报告再滚到某节」：无头模式下带 `#s4` 锚点不会滚动；
 * 用脚本滚又会撞上两条坑——报告里 `scroll-behavior:smooth` 让滚动变成动画，
 * 截图在动到一半时就拍了；改成瞬时滚动，合成器还没出帧，截出来是整页空白。
 * 所以这里干脆不滚：把目标章节从报告里**切出来**单独成页，章节自然在页首。
 * 报告的正文都是 `.wrap` 下的平级节点，按 `<h2 id="sN"` 切片即可。
 *
 * 用法：
 *   node tools/shots.mjs                        生成 assets/screenshot-*.png
 *   node tools/shots.mjs --browser <浏览器路径>   指定 Chromium 内核浏览器
 *   node tools/shots.mjs --report <报告.html>     用已有报告截图，跳过重新生成
 *
 * 环境变量 `EDGE_PATH` / `CHROME_PATH` 与 `--browser` 等价。
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');
const REPORTS = path.join(PKG, 'reports');
const TMP = path.join(REPORTS, '.shots');
const ASSETS = path.join(PKG, 'assets');

/**
 * 要截的图。`section` 为 null 表示用整页（封面 + 目录）。
 * 章节 id 由 `lib/report.js` 生成：s1 概况、s2 结论摘要、s3 分域明细、s4 等保对照。
 */
const SHOTS = [
  { name: '1-overview', section: null, w: 1200, h: 860 },
  { name: '2-summary', section: 's2', w: 1200, h: 760 },
  { name: '3-domains', section: 's3', w: 1200, h: 900 },
  { name: '4-compliance', section: 's4', w: 1200, h: 900 },
];

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? (argv[i + 1] ?? null) : null;
};

/** 找一个可用的 Chromium 内核浏览器；找不到返回 null，由调用方给出可操作的提示。 */
function findBrowser() {
  const explicit = flag('--browser') ?? process.env.EDGE_PATH ?? process.env.CHROME_PATH;
  if (explicit) return fs.existsSync(explicit) ? explicit : null;
  const pf = process.env['ProgramFiles'] ?? 'C:\\Program Files';
  const pf86 = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';
  const local = process.env.LOCALAPPDATA ?? '';
  const cands = [
    path.join(pf86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(pf, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(local, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(pf, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(pf86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    '/usr/bin/microsoft-edge',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ];
  return cands.find((p) => p && fs.existsSync(p)) ?? null;
}

/** 生成一份演示报告，返回文件路径。子进程输出直接继承，避免额外管道。 */
function buildDemoReport() {
  const r = spawnSync(process.execPath, [path.join(HERE, 'catalog.mjs'), 'demo-report'], { cwd: PKG, stdio: 'inherit' });
  if (r.status !== 0) throw new Error(`演示报告生成失败（退出码 ${r.status}）`);
  const files = fs.readdirSync(REPORTS).filter((f) => f.startsWith('dm-security-demo-L3-') && f.endsWith('.html'));
  if (!files.length) throw new Error(`在 ${REPORTS} 下没找到演示报告`);
  files.sort((a, b) => fs.statSync(path.join(REPORTS, b)).mtimeMs - fs.statSync(path.join(REPORTS, a)).mtimeMs);
  return path.join(REPORTS, files[0]);
}

/**
 * 只保留目标章节：头部样式原样保留，正文换成 `.wrap` 下的那一个章节。
 * 章节之间是平级节点，所以按相邻两个 `<h2 id="` 切片得到的 HTML 是配平的。
 */
function sliceSection(html, id) {
  const bodyAt = html.indexOf('<body');
  if (bodyAt < 0) throw new Error('报告里找不到 <body>');
  const head = html.slice(0, html.indexOf('>', bodyAt) + 1);
  const start = html.indexOf(`<h2 id="${id}"`);
  if (start < 0) throw new Error(`报告里找不到章节 #${id}`);
  const bodyEnd = html.lastIndexOf('</body>');
  const next = html.indexOf('<h2 id="', start + 1);
  const end = next >= 0 && next < bodyEnd ? next : html.lastIndexOf('</div>', bodyEnd);
  if (end <= start) throw new Error(`章节 #${id} 的结束位置没找到`);
  return `${head}\n<div class="sheet"><div class="wrap">\n${html.slice(start, end)}\n</div></div></body></html>`;
}

function shoot(browser, url, out, w, h) {
  const args = [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--hide-scrollbars',
    '--force-device-scale-factor=1',
    `--window-size=${w},${h}`,
    `--user-data-dir=${path.join(TMP, 'profile')}`,
    `--screenshot=${out}`,
    url,
  ];
  spawnSync(browser, args, { stdio: 'ignore' });
  return fs.existsSync(out) && fs.statSync(out).size > 20_000;
}

const browser = findBrowser();
if (!browser) {
  console.error('没找到 Chromium 内核浏览器。用 --browser <路径> 或环境变量 EDGE_PATH / CHROME_PATH 指定。');
  process.exit(2);
}

const reportPath = flag('--report') ? path.resolve(flag('--report')) : buildDemoReport();
if (!fs.existsSync(reportPath)) {
  console.error(`报告不存在：${reportPath}`);
  process.exit(2);
}

const fullHtml = fs.readFileSync(reportPath, 'utf8');
fs.mkdirSync(TMP, { recursive: true });
fs.mkdirSync(ASSETS, { recursive: true });
console.log(`\n浏览器：${browser}\n报告：${reportPath}\n`);

let failed = 0;
for (const s of SHOTS) {
  const html = s.section ? sliceSection(fullHtml, s.section) : fullHtml;
  const tmpHtml = path.join(TMP, `${s.name}.html`);
  fs.writeFileSync(tmpHtml, html, 'utf8');
  const out = path.join(ASSETS, `screenshot-${s.name}.png`);
  const url = `file:///${tmpHtml.replace(/\\/g, '/')}`;
  if (shoot(browser, url, out, s.w, s.h)) {
    console.log(`  ${path.relative(PKG, out)}  ${(fs.statSync(out).size / 1024).toFixed(0)} KB  (${s.w}x${s.h}${s.section ? ` · #${s.section}` : ''})`);
  } else {
    console.log(`  ${s.name} 截图失败`);
    failed++;
  }
}
fs.rmSync(TMP, { recursive: true, force: true });
if (failed) {
  console.error(`\n有 ${failed} 张截图失败。`);
  process.exit(1);
}
console.log('\n截图已写入 assets/，路径由 screenshots.json 声明。');
