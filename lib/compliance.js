/**
 * 等保 2.0 控制点表（GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》）。
 *
 * ★ 为什么要有「级别」这一维：等保定级定的是**信息系统**，不是数据库；数据库随系统定级。
 *   标准按级别分章，各级「安全计算环境」的章条号随级别顺延：
 *     第二级 7.1.4.x ／ 第三级 8.1.4.x ／ 第四级 9.1.4.x
 *   所以「按哪一级对照」不只影响结论口径，连条款编号都会变。本表只存**条款序号 + 字母 +
 *   该条款首次出现的级别（minLevel）**，具体编号由 `parseControl(id, level)` 按目标级别拼出。
 *
 * ★ 为什么默认第三级：三级在用得上的范围内基本是二级的超集 —— 按三级对照，二级客户最坏是
 *   「多出几条判不适用」；按二级对照，三级客户会**整条漏掉**双因素、安全标记、审计进程保护、
 *   管理终端限制、漏洞修补、热冗余这一批。漏检的代价远大于多检。四级则不适合当默认：
 *   其增量集中在强制访问控制/四权分立，只有达梦安全版才有对应能力，默认四级会让大量普通版
 *   环境被无意义地判缺失。
 *
 * ⚠️ 另外两条必须说明的事：
 *   1. 下面的「要求」是**摘要**（为便于在报告里展开阅读而压缩了句式），**不是标准原文**；
 *      正式测评请以标准原文与测评机构的判定口径为准。
 *   2. 章条号与条款字母（如 `8.1.4.2(d)`）是**工作基线**：达梦的安全能力与标准条款并非一一对应，
 *      插件给出的是「最贴切的那一条」，用于帮读者定位，不代替测评结论。
 *
 * 级别适用性（minLevel）的取值依据 —— 三级相对二级的增量，在本表用到的范围内是：
 *   身份鉴别 d) 双因素｜访问控制 e/f/g) 授权主体配置策略、粒度、安全标记｜安全审计 d) 审计进程保护｜
 *   入侵防范 c/e/f) 管理终端限制、漏洞修补、入侵检测报警｜数据备份恢复 b) 实时异地、c) 热冗余。
 *   四级在本插件引用到的条款里**没有额外条款**（四级增量集中在强制访问控制与四权分立，
 *   由 `mac.edition` / `mac.policy_objects` 两项覆盖），因此不存在 minLevel: 4 的条款；
 *   选择四级时章条号按 9.1.4.x 给出，并在报告里注明「四级增量未逐条展开，需与测评机构核对」。
 */

/** 默认对照级别（第三级）。 */
export const DEFAULT_COMPLIANCE_LEVEL = 3;

/** 支持的对照级别。等保 2.0 一共五级，插件只做数据库能自证的部分：二/三/四级。 */
export const COMPLIANCE_LEVELS = [2, 3, 4];

/** 级别 → 章条号根：第二级 7.1.4.x / 第三级 8.1.4.x / 第四级 9.1.4.x。 */
export const LEVEL_META = {
  2: { level: 2, chapter: '7', clauseRoot: '7.1.4', label: '第二级', short: '二级' },
  3: { level: 3, chapter: '8', clauseRoot: '8.1.4', label: '第三级', short: '三级' },
  4: { level: 4, chapter: '9', clauseRoot: '9.1.4', label: '第四级', short: '四级' },
};

/** 把任意输入收敛成受支持的级别；不认识的值退回默认级别。 */
export function normalizeLevel(v) {
  const n = Number(v);
  return LEVEL_META[n] ? n : DEFAULT_COMPLIANCE_LEVEL;
}

export function levelMeta(level) {
  return LEVEL_META[normalizeLevel(level)];
}

/** 报告/文本里用的标准名，例如 `GB/T 22239-2019 第三级「安全计算环境」（8.1.4.x）`。 */
export function standardName(level) {
  const m = levelMeta(level);
  return `GB/T 22239-2019 ${m.label}「安全计算环境」（${m.clauseRoot}.x）`;
}

/** 兼容旧引用：默认级别的标准名。 */
export const STANDARD = standardName(DEFAULT_COMPLIANCE_LEVEL);

/**
 * 控制点表。键是**条款序号**（章号由级别决定，所以键里不含章号）。
 *   每个字母：`req` = 要求摘要；`minLevel` = 该条款首次出现的级别；
 *   `req2` = 二级与三级同字母但**措辞不同**时的二级文本（目前只有「异地备份」这一条）。
 */
export const CONTROLS = {
  1: {
    order: 1,
    title: '身份鉴别',
    items: {
      a: { req: '对登录用户进行身份标识和鉴别，身份标识具有唯一性，鉴别信息具有复杂度要求并定期更换', minLevel: 2 },
      b: { req: '具有登录失败处理功能：结束会话、限制非法登录次数、登录连接超时自动退出', minLevel: 2 },
      c: { req: '远程管理时采取必要措施，防止鉴别信息在网络传输过程中被窃听', minLevel: 2 },
      d: { req: '采用口令、密码技术、生物技术等两种或两种以上组合的鉴别技术，且其中至少一种使用密码技术', minLevel: 3 },
    },
  },
  2: {
    order: 2,
    title: '访问控制',
    items: {
      a: { req: '对登录的用户分配账户和权限', minLevel: 2 },
      b: { req: '重命名或删除默认账户，修改默认账户的默认口令', minLevel: 2 },
      c: { req: '及时删除或停用多余的、过期的账户，避免共享账户', minLevel: 2 },
      d: { req: '授予管理用户所需的最小权限，实现管理用户的权限分离', minLevel: 2 },
      e: { req: '由授权主体配置访问控制策略，策略规定主体对客体的访问规则', minLevel: 3 },
      f: { req: '访问控制粒度达到主体为用户级或进程级，客体为文件、数据库表级', minLevel: 3 },
      g: { req: '对重要主体和客体设置安全标记，并控制主体对有安全标记信息资源的访问', minLevel: 3 },
    },
  },
  3: {
    order: 3,
    title: '安全审计',
    items: {
      a: { req: '启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计', minLevel: 2 },
      b: { req: '审计记录包括事件的日期时间、用户、事件类型、事件是否成功及其他审计相关信息', minLevel: 2 },
      c: { req: '对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖', minLevel: 2 },
      d: { req: '对审计进程进行保护，防止未经授权的中断', minLevel: 3 },
    },
  },
  4: {
    order: 4,
    title: '入侵防范',
    items: {
      a: { req: '遵循最小安装原则，仅安装需要的组件和应用程序', minLevel: 2 },
      b: { req: '关闭不需要的系统服务、默认共享和高危端口', minLevel: 2 },
      c: { req: '通过设定终端接入方式或网络地址范围，对通过网络进行管理的管理终端进行限制', minLevel: 3 },
      d: { req: '提供数据有效性检验功能，保证人机接口或通信接口输入的内容符合系统设定要求', minLevel: 2 },
      e: { req: '能发现可能存在的已知漏洞，并在经过充分测试评估后及时修补', minLevel: 3 },
      f: { req: '能检测到对重要节点进行入侵的行为，并在发生严重入侵事件时提供报警', minLevel: 3 },
    },
  },
  7: {
    order: 7,
    title: '数据完整性',
    items: {
      a: { req: '采用校验技术或密码技术保证重要数据在传输过程中的完整性', minLevel: 2 },
      b: { req: '采用校验技术或密码技术保证重要数据在存储过程中的完整性', minLevel: 2 },
    },
  },
  8: {
    order: 8,
    title: '数据保密性',
    items: {
      a: { req: '采用密码技术保证重要数据在传输过程中的保密性', minLevel: 2 },
      b: { req: '采用密码技术保证重要数据在存储过程中的保密性', minLevel: 2 },
    },
  },
  9: {
    order: 9,
    title: '数据备份恢复',
    items: {
      a: { req: '提供重要数据的本地数据备份与恢复功能', minLevel: 2 },
      b: {
        req: '提供异地实时备份功能，利用通信网络将重要数据实时备份至备份场地',
        req2: '提供异地数据备份功能，利用通信网络将重要数据定时批量传送至备用场地',
        minLevel: 2,
      },
      c: { req: '提供重要数据处理系统的热冗余，保证系统的高可用性', minLevel: 3 },
    },
  },
  10: {
    order: 10,
    title: '剩余信息保护',
    items: {
      a: { req: '保证鉴别信息所在的存储空间被释放或重新分配前得到完全清除', minLevel: 2 },
      b: { req: '保证存有敏感数据的存储空间被释放或重新分配前得到完全清除', minLevel: 2 },
    },
  },
};

/** 条款 ID 解析：接受 `8.1.4.2(d)`（带任意章号）或 `2(d)`（只给序号与字母）。 */
const CONTROL_RE = /^(?:\d+\.[0-9.]+\.)?(\d+)\(([a-z])\)$/;

/**
 * 解析条款 ID → 目标级别下的条款对象；解析不了返回 null。
 *
 * `8.1.4.2(d)` 在 checks.js 里是**规范写法**（用第三级编号书写，与标准原文一致），
 * 这里接受任意章号并**按目标级别重写**编号 —— 所以二级对照时同一项输出 `7.1.4.2(d)`。
 */
export function parseControl(id, level = DEFAULT_COMPLIANCE_LEVEL) {
  const m = CONTROL_RE.exec(String(id ?? '').trim());
  if (!m) return null;
  const clause = CONTROLS[m[1]];
  if (!clause) return null;
  const item = clause.items[m[2]] ?? null;
  const meta = levelMeta(level);
  const minLevel = item?.minLevel ?? 2;
  const requirement = meta.level === 2 && item?.req2 ? item.req2 : (item?.req ?? null);
  const control = `${meta.clauseRoot}.${m[1]}(${m[2]})`;
  return {
    id: control,
    clause: m[1],
    clauseIndex: Number(m[1]),
    letter: m[2],
    title: clause.title,
    order: clause.order,
    requirement,
    minLevel,
    /** 该条款在当前对照级别下是否适用（三级专属条款在二级对照下为 false） */
    applicable: meta.level >= minLevel,
    /** 报告里用的紧凑标签：`8.1.4.2(d) 访问控制 · 授予管理用户所需的最小权限，实现管理用户的权限分离` */
    label: `${control} ${clause.title}${requirement ? ` · ${requirement}` : ''}`,
  };
}

/**
 * 一组条款里**最低**的适用级别 = 该检查项开始适用的级别。
 * 语义：只要有一条映射条款在当前级别已存在，这项检查就该判（不能因为捆绑了一条高等级条款就整项不判）。
 * 没有映射（加固项）返回 1 —— 加固建议与级别无关，任何级别都给出。
 */
export function minLevelOf(ids) {
  const parsed = (ids ?? []).map((i) => parseControl(i, DEFAULT_COMPLIANCE_LEVEL)).filter(Boolean);
  if (!parsed.length) return 1;
  return Math.min(...parsed.map((p) => p.minLevel));
}

/** 该组条款在当前对照级别下是否适用。 */
export function isApplicableAt(ids, level) {
  return levelMeta(level).level >= minLevelOf(ids);
}

/**
 * 级别口径说明（报告/文本里原样展示）。
 * 把「为什么有些项被判不适用」写在报告里，读者才不会把级别差异当成安全缺陷。
 */
export function levelBasis(level) {
  const lv = normalizeLevel(level);
  const m = LEVEL_META[lv];
  const common = `本报告按 **${m.label}**（${m.clauseRoot}.x）对照：等保定级定的是信息系统，数据库随系统定级，级别不同则条款编号与要求范围都不同。`;
  const notes = {
    2: [
      '三级相对二级的增量条款（双因素鉴别、安全标记、审计进程保护、管理终端接入限制、漏洞修补、实时异地备份与热冗余等）在二级对照下判**「不适用」**，不计为不符合；但这些项在报告里仍保留技术结论，便于将来升级到三级时直接复用。',
      '二级同样要求：账户与权限分配（含最小权限与权限分离）、默认账户处理、多余/过期账户清理、登录失败处理、安全审计及审计记录保护、关闭不需要的服务与端口、数据完整性与保密性、本地备份恢复。',
    ],
    3: [
      '三级是插件默认的对照级别：它在本插件用到的范围内基本覆盖二级，因此按三级做自查的结论可直接用于三级系统，二级系统只需把高等级专属条款按级别降级即可。',
      '四级相对三级的增量集中在强制访问控制与四权分立，属安全版能力，不在本表条款内；如为四级系统，请另外确认这两项。',
    ],
    4: [
      '四级章条号按级别顺延为 9.1.4.x（工作基线）。四级相对三级的增量（强制访问控制、四权分立等）**未逐条展开**：本插件用 mac.edition / mac.policy_objects 两项覆盖强制访问控制与安全标记能力，正式测评项请与测评机构核对。',
      '四级通常伴随更严格的审计与集中管控要求（安全管理中心侧），其中相当一部分不在数据库自身可自证的范围内。',
    ],
  }[lv];
  return { level: lv, label: m.label, clauseRoot: m.clauseRoot, standard: standardName(lv), basis: common, notes };
}

/** 报告「控制点映射」一节用：按章条分组的行（编号按目标级别给出）。 */
export function controlTable(ids, level = DEFAULT_COMPLIANCE_LEVEL) {
  const lv = normalizeLevel(level);
  const seen = new Map();
  for (const id of ids ?? []) {
    const p = parseControl(id, lv);
    if (!p) continue;
    if (!seen.has(p.id)) {
      seen.set(p.id, {
        id: p.id,
        clause: p.clause,
        letter: p.letter,
        title: p.title,
        order: p.order,
        requirement: p.requirement,
        minLevel: p.minLevel,
        applicable: p.applicable,
      });
    }
  }
  return [...seen.values()].sort((x, y) => x.order - y.order || x.letter.localeCompare(y.letter));
}
