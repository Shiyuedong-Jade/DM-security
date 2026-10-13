/**
 * 文档语气自检：扫描文档里的 AI 写作痕迹。
 *
 * 由来：README / SECURITY / CHANGELOG 按 `DM-inspect` 的写法重写后，DESIGN.md 仍是旧腔调。
 * 与其靠人眼通读 700 行，不如把**可机械识别的痕迹**列出来（去 AI 味的规则本身是白名单式的，
 * 每条都有可定位的触发标记），改完再让自检守住零命中。
 *
 * 只报**能定位、能判定**的模式；句长、段落长度、被动句、名词化这些实测无差异的特征不查。
 *
 * 用法：
 *   node tools/doc-tone.mjs            # 扫描仓库内文档，列出命中行
 *   node tools/doc-tone.mjs --quiet     # 只输出统计（自检用）
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');
const QUIET = process.argv.includes('--quiet');

/** 要扫的文档。 */
const DOCS = ['README.md', 'SECURITY.md', 'CHANGELOG.md', 'DESIGN.md'];

/**
 * 痕迹模式。`mechanical: true` 表示零容忍（可进自检断言）；
 * 其余只提示，因为要按上下文判断，不能机械替换。
 */
export const PATTERNS = [
  { key: 'dash', label: '破折号', re: /——/g, mechanical: true },
  {
    key: 'reversal',
    label: '翻案句（不是…而是 / 并非…而是 / 不在于…而在于 / 与其说…不如说）',
    re: /不是[^。；\n]{0,25}而是|并非[^。；\n]{0,25}而是|不在于[^。；\n]{0,25}而在于|与其说[^。；\n]{0,25}不如说/g,
    mechanical: true,
  },
  { key: 'opener', label: '起手式（说白了 / 说穿了 / 先说结论）', re: /说白了|说穿了|先说结论/g, mechanical: true },
  {
    key: 'colonLead',
    label: '提示语引出的冒号（一句话总结 / 核心是 / 关键在于 …：）',
    re: /(一句话总结|核心是|关键在于|原因如下|本质上|换句话说|结论是)[^。\n]{0,10}：/g,
    mechanical: true,
  },
  { key: 'emoji', label: 'emoji', re: /[\u2600-\u27BF\uD83C-\uDBFF\uDC00-\uDFFF]/g, mechanical: true },
  { key: 'badge', label: '徽章', re: /!\[[^\]]*\]\(https:\/\/img\.shields\.io|badge\.svg/g, mechanical: true },
  { key: 'anthropo', label: '拟人化喻体（像一位导师 / 不知疲倦的助手）', re: /像(一位|一个|一名)[^。\n]{0,12}(导师|秘书|顾问|管家|助手|审查员|实习生)/g },
  { key: 'thisMeans', label: '「这意味着 / 这表明」式复述', re: /(这意味着|这表明|这说明)[^。\n]{0,30}/g },
  { key: 'whenClause', label: '「当…时，」前置时间从句', re: /当[^。\n]{0,40}时，/g },
  { key: 'topicShell', label: '前置话题壳（对于…来说 / 就…而言 / 在…方面）', re: /(对于[^。\n]{0,20}来说|对[^。\n]{0,20}而言|就[^。\n]{0,20}而言|在[^。\n]{0,12}方面)/g },
  { key: 'leader', label: '句首连接词（然而，/ 此外，/ 因此，/ 与此同时，）', re: /(^|[。；\n])(然而|此外|因此|与此同时|换言之|总而言之)，/g },
  { key: 'boldHeading', label: '整行加粗当小标题', re: /^\s*\*\*[^*\n]{4,40}\*\*\s*$/gm },
];

/** 逐文件扫描，返回 { file, key, label, line, text } 列表。 */
export function scanText(text, file = '(text)') {
  const lines = String(text ?? '').split('\n');
  const hits = [];
  for (const p of PATTERNS) {
    lines.forEach((line, i) => {
      if (p.re.test(line)) hits.push({ file, key: p.key, label: p.label, line: i + 1, text: line.trim().slice(0, 120) });
      p.re.lastIndex = 0;
    });
  }
  return hits;
}

export function scanDocs(docs = DOCS) {
  return docs.flatMap((f) => {
    const p = path.join(PKG, f);
    return fs.existsSync(p) ? scanText(fs.readFileSync(p, 'utf8'), f) : [];
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const hits = scanDocs();
  const byKey = new Map();
  for (const h of hits) byKey.set(h.key, (byKey.get(h.key) ?? 0) + 1);
  if (!QUIET) {
    for (const f of DOCS) {
      const own = hits.filter((h) => h.file === f);
      if (!own.length) continue;
      console.log(`\n=== ${f}（${own.length} 处）===`);
      for (const h of own) console.log(`  ${h.line}: [${h.label}] ${h.text}`);
    }
  }
  console.log('\n合计：');
  for (const p of PATTERNS) console.log(`  ${String(byKey.get(p.key) ?? 0).padStart(3)}  ${p.label}${p.mechanical ? '（零容忍）' : ''}`);
  console.log(`  总计 ${hits.length} 处`);
}
