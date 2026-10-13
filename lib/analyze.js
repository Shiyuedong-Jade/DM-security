/**
 * 评估引擎：把采集回来的原始结果变成逐项结论与等保合规映射。
 *
 * 六态结论（DESIGN §2.1）：
 *   crit 严重 / warn 警告 / info 提示 / ok 合规 / na 不适用 / unknown 未取到
 *
 * 「不适用」与「未取到」都不进结论统计（本工具不评分）—— 这是本插件最重要的口径：
 *   普通版没有强制访问控制是**产品形态**，不是安全缺陷；
 *   高等级专属条款在你定级的那一级**本来就不是测评项**，判不适用而不是不符合；
 *   没拿到数据就说没拿到，不能默认判合规，也不能默认判不合规。
 */

import { CHECKS, DOMAINS, KNOWN_ROLES } from './checks.js';
import { parseControl, minLevelOf, levelMeta, normalizeLevel, DEFAULT_COMPLIANCE_LEVEL } from './compliance.js';
import { col, num, isBuiltin, hasCol } from './util.js';

export const LEVELS = ['crit', 'warn', 'info', 'ok', 'na', 'unknown'];
export const LEVEL_LABEL = {
  crit: '严重',
  warn: '警告',
  info: '提示',
  ok: '合规',
  na: '不适用',
  unknown: '未取到',
};
export const LEVEL_ORDER = ['crit', 'warn', 'ok', 'info', 'na', 'unknown'];

/** 权重只用于「最要紧的几件事」排序（评分已取消，不再参与任何计分）。 */
const ITEM_WEIGHT = { crit: 10, warn: 4, info: 1 };

/** 采集结果规范化：行数组 → 行对象；并丢弃口令散列列。 */
export function rowsToObjects(res) {
  if (!res) return { columns: [], rows: [], error: 'NO_RESULT', sqlUsed: null, truncated: false };
  const columns = Array.isArray(res.columns) ? res.columns : [];
  const raw = Array.isArray(res.rows) ? res.rows : [];
  const rows = raw.map((r) => {
    if (r && !Array.isArray(r) && typeof r === 'object') return r;
    if (!Array.isArray(r)) return {};
    const o = {};
    columns.forEach((c, i) => {
      o[c] = r[i];
    });
    return o;
  });
  return {
    columns,
    rows: redact(rows),
    error: res.error ?? null,
    sqlUsed: res.sqlUsed ?? null,
    truncated: Boolean(res.truncated),
  };
}

/**
 * 丢弃口令/密钥类列。
 *
 * 为什么必须有这一层：`SYSUSERS` 的列里有 **`PASSWORD` / `OLD_PASSWORD` / `ENCRYPT_KEY`**，
 * `DBA_USERS` 有 `PASSWORD`。任何一条降级到 `SELECT *` 的查询都会把散列/密钥带进结果文件。
 * 真机核对时用 `SELECT * FROM SYSUSERS` 就亲眼看到了这三列 —— 所以名单必须完整，
 * 只挡 `PASSWORD` 是不够的。
 */
const SECRET_COL_RE = /^(PASSWORD|OLD_PASSWORD|PASSWD|PWD|PASSWORD_HASH|PWD_HASH|ENCRYPT_KEY|SECRET|HASH)$/i;
export function redact(rows) {
  return rows.map((r) => {
    const keys = Object.keys(r).filter((k) => SECRET_COL_RE.test(k));
    if (keys.length === 0) return r;
    const copy = { ...r };
    for (const k of keys) copy[k] = '***';
    return copy;
  });
}

/**
 * 把整张采集结果规范化（逐 key 走 `rowsToObjects`）。
 *
 * 必须在任何判定之前做：`detectShape()` 之类的函数要按列名读 `V$INSTANCE`，
 * 而 JDBC 桥给的是「列名数组 + 行数组」形态；不先规范化，形态识别会静默拿到 undefined
 * （表现为版本号为空、判定悄悄走偏，是最难查的一类缺陷）。
 */
export function normalizeAll(data) {
  const out = {};
  for (const [k, v] of Object.entries(data ?? {})) {
    if (v === undefined || v === null) continue;
    out[k] = rowsToObjects(v);
  }
  return out;
}

/** 参数表 → Map（键统一大写）。 */
export function paramMap(res) {
  const map = new Map();
  for (const r of res?.rows ?? []) {
    const name = String(col(r, 'PARA_NAME', 'NAME') ?? '').trim();
    if (!name) continue;
    map.set(name.toUpperCase(), {
      name,
      value: col(r, 'PARA_VALUE', 'VALUE') ?? null,
      fileValue: col(r, 'FILE_VALUE') ?? null,
      min: col(r, 'MIN_VALUE') ?? null,
      max: col(r, 'MAX_VALUE') ?? null,
      def: col(r, 'DEFAULT_VALUE') ?? null,
      desc: col(r, 'DESCRIPTION') ?? null,
    });
  }
  return map;
}

/** 账号规范化。`builtin` 只用于把「安装默认状态」降级为 info（见 util.js 的说明）。 */
export function normalizeUsers(res) {
  return (res?.rows ?? []).map((r) => {
    const name = String(col(r, 'USERNAME', 'USER_NAME', 'NAME') ?? '').trim();
    return {
      name,
      id: col(r, 'USER_ID', 'ID') ?? null,
      status: String(col(r, 'ACCOUNT_STATUS', 'STATUS$', 'STATUS') ?? '').trim().toUpperCase(),
      authType: String(col(r, 'AUTHENTICATION_TYPE', 'AUTH_TYPE') ?? '').trim(),
      lockDate: col(r, 'LOCK_DATE') ?? null,
      expiryDate: col(r, 'EXPIRY_DATE') ?? null,
      created: col(r, 'CREATED_AT', 'CREATED') ?? null,
      tablespace: col(r, 'DEFAULT_TABLESPACE') ?? null,
      builtin: isBuiltin(name),
    };
  });
}

/**
 * 口令策略/资源限制规范化。
 *
 * ⚠️ 真机（10.0.0.40，DM8 企业版 8.1.3）实测的 `SYSUSERS` 列名：
 *    `PWD_POLICY / LIFE_TIME / FAILED_NUM / FAILED_ATTEMPS / LOCK_TIME / CONN_IDLE_TIME /
 *     SESS_PER_USER / REUSE_MAX / REUSE_TIME / ALLOW_ADDR / NOT_ALLOW_ADDR / ALLOW_DT /
 *     LAST_LOGIN_DTID / LAST_LOGIN_IP`
 * 原来的实现按 `SESSION_PER_USER` / `CPU_PER_SESSION` / `MEM_SPACE` 取数，在真机上**一个都不存在**；
 * 保留旧名作为候选只是防御，实际以真机列名为准。列不存在时相应检查项判「未取到」。
 */
export function normalizePwd(res) {
  const cols = res?.columns ?? [];
  const has = (n) => cols.some((c) => String(c).toUpperCase() === n.toUpperCase());
  return {
    columns: cols,
    sessionColumnPresent: has('SESS_PER_USER') || has('SESSION_PER_USER'),
    reuseColumnPresent: has('REUSE_MAX') || has('REUSE_TIME'),
    accessColumnPresent: has('ALLOW_ADDR') || has('NOT_ALLOW_ADDR') || has('ALLOW_IP') || has('NOT_ALLOW_IP'),
    lastLoginColumnPresent: has('LAST_LOGIN_DTID') || has('LAST_LOGIN'),
    rows: (res?.rows ?? []).map((r) => ({
      name: String(col(r, 'USERNAME', 'USER_NAME') ?? '').trim(),
      policy: col(r, 'PWD_POLICY') ?? null,
      lifeDays: num(col(r, 'PWD_LIFE_DAYS', 'LIFE_TIME')),
      failedNum: num(col(r, 'FAILED_NUM')),
      failedAttemps: num(col(r, 'FAILED_ATTEMPS', 'FAILED_ATTEMPTS')),
      lockTime: num(col(r, 'LOCK_TIME')),
      idleTime: num(col(r, 'CONN_IDLE_TIME')),
      sessionsPerUser: num(col(r, 'SESS_PER_USER', 'SESSION_PER_USER', 'SESSIONS_PER_USER')),
      reuseMax: num(col(r, 'REUSE_MAX')),
      reuseTime: num(col(r, 'REUSE_TIME')),
      allowAddr: col(r, 'ALLOW_ADDR', 'ALLOW_IP') ?? null,
      notAllowAddr: col(r, 'NOT_ALLOW_ADDR', 'NOT_ALLOW_IP') ?? null,
      allowDt: col(r, 'ALLOW_DT', 'ALLOW_DATETIME') ?? null,
      lastLogin: col(r, 'LAST_LOGIN_DTID', 'LAST_LOGIN') ?? null,
      lastLoginIp: col(r, 'LAST_LOGIN_IP') ?? null,
      builtin: isBuiltin(String(col(r, 'USERNAME', 'USER_NAME') ?? '')),
    })),
  };
}

/**
 * PROFILE 资源限制（`DBA_PROFILES`）。
 *
 * ⚠️ 真机纠正：按用户的 CPU / 内存 / 单用户会话数限制**不在 `SYSUSERS`**，
 * 而在 `DBA_PROFILES`（列：`PROFILE / RESOURCE_NAME / RESOURCE_TYPE / LIMIT`），
 * 取值 `UNLIMITED` 表示不限制。原来把 `res.cpu_limit` / `res.mem_limit` 判成「未取到」，
 * 真机上其实**可判定**（这里是关键改进）。
 */
export function profileMap(res) {
  const map = new Map();
  for (const r of res?.rows ?? []) {
    const p = String(col(r, 'PROFILE', 'NAME') ?? 'DEFAULT').trim().toUpperCase();
    const name = String(col(r, 'RESOURCE_NAME', 'RESOURCE') ?? '').trim().toUpperCase();
    if (!name) continue;
    const raw = col(r, 'LIMIT', 'LIMIT_VALUE');
    const v = String(raw ?? '').trim().toUpperCase();
    const type = String(col(r, 'RESOURCE_TYPE') ?? '').trim().toUpperCase();
    if (!map.has(p)) map.set(p, new Map());
    map.get(p).set(name, { raw: raw ?? null, value: v, unlimited: v === 'UNLIMITED', type });
  }
  return map;
}

/** 从 PROFILE 取一个资源限制；`profile` 默认 DEFAULT。 */
export function profileLimit(profiles, resource, profile = 'DEFAULT') {
  return profiles.get(String(profile).toUpperCase())?.get(String(resource).toUpperCase()) ?? null;
}

/**
 * 形态与版本前提（DESIGN §3）。
 *
 * ★ 版本类型以 **`V$INSTANCE.ID_CODE` 解码出的 `BUILD_TYPE`** 为**唯一权威判据**。
 *
 * 为什么改（2026-10-12 真机教训，10.0.0.40）：原来的实现用「两个独立信号」——
 * `PRIV_FLAG` 参数存在，或 `DBA_OBJECTS` 里有 MAC 策略/标记对象。真机上该实例是
 * **企业版（普通版）**，但字典里照样有 `SYSMACLABELS` / `VSYSMACLABELS` 与 `DB_POLICY_*` 角色，
 * 于是被误判为「安全版」：`mac.edition` 报「能力可用」、`ident.admin_accounts` 走安全版分支
 * 去警告管理员账号不可用 —— 而正确答案是「强制访问控制**不适用**」。
 *
 * 现在：有 `BUILD_TYPE` 就信它；取不到时才退回旧的两个信号，并在信号列表里标明是**降级判据**。
 */
export function detectShape(data) {
  const params = paramMap(data.params);
  const macRows = data.macObjs?.rows ?? [];
  const bt = data.buildType?.rows?.[0] ?? {};
  const editionRaw = String(col(bt, 'BUILD_TYPE') ?? '').trim();
  const idCode = String(col(bt, 'ID_CODE') ?? '').trim();
  const edition = editionRaw && editionRaw !== '其他' ? editionRaw : null;

  const signals = [];
  if (edition) signals.push(`BUILD_TYPE=${edition}`);
  if (idCode) signals.push(`ID_CODE=${idCode}`);
  if (params.has('PRIV_FLAG')) signals.push(`参数 PRIV_FLAG=${params.get('PRIV_FLAG').value ?? ''}`);
  if (macRows.length > 0) signals.push(`MAC 字典对象 ${macRows.length} 个（普通版字典里也存在，不能据此判版）`);

  // 有权威版本类型就信它；否则退回旧信号（并会在文案里说明是降级判据）
  const secure = edition ? edition === '安全版' : params.has('PRIV_FLAG');

  const inst = data.instance?.rows?.[0] ?? {};
  const db = data.database?.rows?.[0] ?? {};
  const dscNodes = num(col(db, 'DSC_NODES'));
  const isDw =
    num(data.dwApply?.rows?.[0] ? col(data.dwApply.rows[0], 'CNT') : null) > 0 ||
    num(data.dwSend?.rows?.[0] ? col(data.dwSend.rows[0], 'CNT') : null) > 0;
  // ---- 版本与实例信息（取法与展示对齐 02 组巡检插件的「基础信息」一组）----
  const rt = data.instanceRuntime?.rows?.[0] ?? {};
  const cs = data.charset?.rows?.[0] ?? {};
  const lic = data.license?.rows?.[0] ?? {};
  const daysLeft = num(col(lic, 'DAYS_LEFT'));
  return {
    secure,
    edition,
    idCode: idCode || null,
    editionSource: edition ? 'ID_CODE 解码（权威）' : '降级判据（未取到 BUILD_TYPE）',
    /** 四位内核版本号（由 ID_CODE 解出，同 02 组 basic.build）；兼容 INNER_VISION 这一别名拼写 */
    innerVersion: String(col(bt, 'INNER_VERSION', 'INNER_VISION') ?? '').trim() || null,
    secureSignals: signals,
    macObjectCount: macRows.length,
    privFlag: params.get('PRIV_FLAG')?.value ?? null,
    privMode: params.has('PRIV_FLAG') ? (String(params.get('PRIV_FLAG').value) === '1' ? '四权分立' : '三权分立') : null,
    dscNodes: dscNodes ?? 0,
    cluster: (dscNodes ?? 0) > 1 ? 'DMDSC 共享存储集群' : isDw ? '数据守护主备' : '单实例',
    /**
     * DSC 节点名（来自 `V$DSC_EP_INFO`）。
     * 注意该视图**只有名字、没有地址列**（09 组实测），所以「对端节点」无法自动发现，
     * 必须由调用方通过 `targets` 给出 —— 这里只用来把节点名写进报告。
     */
    epNames: (data.dscEp?.rows ?? []).map((r) => String(col(r, 'EP_NAME') ?? '').trim()).filter(Boolean),
    version: String(col(inst, 'SVR_VERSION', 'SVERSION') ?? '').trim() || null,
    build: String(col(inst, 'BUILD_VERSION', 'BUILD') ?? '').trim() || null,
    instanceName: String(col(inst, 'INSTANCE_NAME') ?? '').trim() || null,
    hostName: String(col(inst, 'HOST_NAME') ?? '').trim() || null,
    dbName: String(col(db, 'NAME') ?? '').trim() || null,
    role: String(col(db, 'ROLE$', 'ROLE') ?? '').trim() || null,
    archMode: String(col(db, 'ARCH_MODE') ?? '').trim() || null,
    startTime: String(col(rt, 'START_TIME') ?? '').trim() || null,
    runDays: num(col(rt, 'RUN_DAYS')),
    charset: {
      unicodeFlag: col(cs, 'UNICODE_FLAG') ?? null,
      caseSensitive: col(cs, 'CASE_SENSITIVE') ?? null,
      extentSize: col(cs, 'EXTENT_SIZE') ?? null,
      pageSizeBytes: col(cs, 'PAGE_SIZE_BYTES') ?? null,
    },
    license: {
      seriesNo: col(lic, 'SERIES_NO') ?? null,
      serverSeries: col(lic, 'SERVER_SERIES') ?? null,
      serverType: col(lic, 'SERVER_TYPE') ?? null,
      serverVer: col(lic, 'SERVER_VER') ?? null,
      expiredDate: col(lic, 'EXPIRED_DATE') ?? null,
      customer: col(lic, 'AUTHORIZED_CUSTOMER') ?? null,
      maxCpu: col(lic, 'MAX_CPU_NUM') ?? null,
      daysLeft,
      /** 授权剩余不足 90 天为提醒线、不足 30 天为严重线（与 02 组 basic.license 同口径） */
      state: daysLeft === null ? 'unknown' : daysLeft < 0 ? 'expired' : daysLeft < 30 ? 'crit' : daysLeft < 90 ? 'warn' : 'ok',
    },
  };
}

/** 阈值默认值。全部可在工具参数里覆盖——评估口径是业务决策，不该写死在代码里。 */
export const DEFAULT_THRESHOLDS = {
  pwdPolicyMin: 31,        // PWD_POLICY 位掩码：同名+长度+大写+数字+标点
  pwdMinLen: 8,            // 口令最小长度（等保三级实践值，建议 9）
  pwdLifeMaxDays: 180,     // 口令有效期上限
  failedLoginMax: 5,       // 失败锁定次数上限
  lockTimeMinMin: 1,       // 锁定持续时长下限（分钟）
  sessionShareWarn: 50,    // 单一来源占会话总数超过该百分比 → 提示
  maxSessionsWarnPct: 80,  // MAX_SESSIONS 使用率告警线
  dormantDays: 90,         // 账号休眠判定：超过该天数未登录 → 警告（真机有 LAST_LOGIN_DTID 可用）
};

function buildContext(data, opts) {
  const params = paramMap(data.params);
  const pwd = normalizePwd(data.pwdPolicy ?? {});
  const users = normalizeUsers(data.users ?? {});
  const profiles = profileMap(data.profiles ?? {});
  const th = { ...DEFAULT_THRESHOLDS, ...(opts.thresholds ?? {}) };
  const roleSet = (() => {
    const set = new Set(KNOWN_ROLES);
    for (const r of data.roles?.rows ?? []) {
      const n = String(col(r, 'ROLE', 'NAME', 'ROLE_NAME') ?? '').trim().toUpperCase();
      if (n) set.add(n);
    }
    return set;
  })();
  const ctx = {
    res: data,
    params,
    pwd,
    users,
    profiles,
    th,
    /** 等保对照级别（2/3/4，默认 3）——决定「高等级专属条款」是否判不适用，以及条款编号的章号 */
    complianceLevel: normalizeLevel(opts.complianceLevel),
    /**
     * 主机侧采集结果（P2）：
     *   `null`         = 本次未启用 OS 访问（check 判 na，并说明怎么开）
     *   `{state:'unknown'}` = 配了 SSH 但没拿到事实（check 判 unknown，附 plink 原因）
     *   `{state:'ok', facts}` = 正常判定
     * 三态区分写在 `checks.js` 的 `osGate()` 里 —— 混成一种就会出现「谎报原因」。
     */
    os: opts.os ?? null,
    shape: detectShape(data),
    isBuiltin,
    p: (name) => params.get(String(name).toUpperCase()) ?? null,
    pv: (name) => params.get(String(name).toUpperCase())?.value ?? null,
    rows: (key) => data[key]?.rows ?? [],
    errorOf: (key) => data[key]?.error ?? (data[key] ? null : 'NO_RESULT'),
    hasCol,
    num,
    col,
    /** 业务账号（非内置、非采集账号）——绝大多数判定只作用在它们身上。 */
    biz: () => users.filter((u) => !u.builtin),
    /** 业务账号的口令/资源限制行。 */
    bizPwd: () => pwd.rows.filter((r) => !r.builtin),
    /** 取 PROFILE 资源限制（默认 DEFAULT profile）；返回 null 表示该配置项未取到。 */
    prof: (resource, profile = 'DEFAULT') => profileLimit(profiles, resource, profile),
    /**
     * 角色名集合。
     *
     * ★ 真机教训（2026-10-12）：达梦把强权限挂在**内置角色**上（`DBA` 角色本身就带
     * `GRANT ANY ...` / `ALTER USER` 与一堆 ANY 权限），而 `DBA_SYS_PRIVS.GRANTEE` 里
     * 出现的是**角色名**。不区分「授予角色」与「授予账号」，就会把「DBA 角色设计如此」
     * 报成「有 10 条 GRANT ANY 授予非默认账号」—— 真机上直接产出 3 条严重误报。
     */
    roleNames: () => {
      const set = new Set(KNOWN_ROLES);
      for (const r of data.roles?.rows ?? []) {
        const n = String(col(r, 'ROLE', 'NAME', 'ROLE_NAME') ?? '').trim().toUpperCase();
        if (n) set.add(n);
      }
      return set;
    },
    isRole: (name) => roleSet.has(String(name ?? '').trim().toUpperCase()),
    /** 管理员账号（按形态给期望集合） */
    admins: () => {
      const expected = ctx.shape.privMode === '四权分立'
        ? ['SYSDBA', 'SYSSSO', 'SYSAUDITOR', 'SYSDBO']
        : ['SYSDBA', 'SYSSSO', 'SYSAUDITOR'];
      return expected.map((n) => ({ name: n, user: users.find((u) => u.name.toUpperCase() === n) ?? null }));
    },
  };
  return ctx;
}

/** 业务账号（非内置）——保留了旧签名，内部走 ctx.biz()。 */
export function bizUsers(ctx) {
  return ctx.users.filter((u) => !u.builtin);
}

/**
 * 报告 / 文本共用的 meta 构造。
 *
 * ★ 为什么必须收成一个函数：2026-10-12 加「版本与实例信息」时，工具路径（index.js）把
 *   `innerVersion / charset / license` 放进了 meta，而验证脚本（live-assess.mjs）自己手拼了一份
 *   没带的 meta —— 结果真机查询明明取到了值，报告里却显示「未取到」，属于**误导性输出**。
 *   凡是「同一份信息在多处拼装」的地方，都会长成这个问题；统一在这里构造。
 */
export function buildMeta(shape, extra = {}) {
  return {
    instanceName: shape.instanceName,
    hostName: shape.hostName,
    dbName: shape.dbName,
    version: shape.version,
    build: shape.build,
    cluster: shape.cluster,
    epNames: shape.epNames,
    role: shape.role,
    archMode: shape.archMode,
    secure: shape.secure,
    secureSignals: shape.secureSignals,
    privMode: shape.privMode,
    edition: shape.edition,
    idCode: shape.idCode,
    innerVersion: shape.innerVersion,
    startTime: shape.startTime,
    runDays: shape.runDays,
    charset: shape.charset,
    license: shape.license,
    ...extra,
  };
}

/**
 * 执行全部检查项，产出结论与等保合规映射。
 *
 * 判定顺序（每一层都能给出**非空原因**，这是验收标准 3）：
 *   版本前提 → 权限前提 → 依赖查询是否取到 → 检查项自己的判定函数
 */
export function runChecks(rawData, opts = {}) {
  const data = normalizeAll(rawData);
  const ctx = buildContext(data, opts);
  const grantedPrivs = new Set(opts.privs ?? ['SYSDBA']);
  const results = [];

  for (const item of CHECKS) {
    const base = {
      id: item.id,
      domain: item.domain,
      title: item.title,
      level: 'unknown',
      message: '',
      advice: item.advice ?? null,
      compliance: item.compliance ?? [],
      // 主机侧（os 域）的检查走 SSH 而不是数据库连接，所以显式声明 `priv: null` = 不要求库权限；
      // 其余项沿用「未声明即按 SYSDBA」的旧口径（缺省值放宽会让漏写 priv 的项悄悄绕过权限闸门）。
      priv: item.priv === null ? null : (item.priv ?? 'SYSDBA'),
      queries: item.needs ?? [],
      weight: ITEM_WEIGHT[item.level] ?? 1,
      hardening: item.hardening ?? null,
      /** 本条开始适用的等保级别（1 = 加固项，与级别无关） */
      minLevel: minLevelOf(item.compliance ?? []),
      complianceLevel: ctx.complianceLevel,
    };
    results.push({ ...base, ...judgeOne(item, ctx, grantedPrivs) });
  }

  // ★ 2026-10-12 按用户要求**取消评分**。
  //   理由：加权评分会把「哪些是硬性不符合、哪些是加固建议」压成一个数字，读者容易只盯分数
  //   而不看具体项；等保测评本身也不给分（逐条判符合/部分符合/不符合）。现在只输出
  //   **结论分布**（六态计数）与逐项结论 —— 数字少了，但信息量没有损失。
  const counts = Object.fromEntries(LEVELS.map((lv) => [lv, results.filter((r) => r.level === lv).length]));
  const assessed = results.filter((r) => ['crit', 'warn', 'ok'].includes(r.level));
  /** 因「本级无此条款」而判不适用的项（与产品形态导致的 na 区分开） */
  const naByLevel = results.filter((r) => r.levelApplicability === 'below-level');

  return {
    shape: ctx.shape,
    results,
    counts,
    /** 本次对照的等保级别（2/3/4） */
    complianceLevel: ctx.complianceLevel,
    /** 因级别差异判「不适用」的项数：二级对照时三级专属条款会落到这里 */
    naByLevel: naByLevel.length,
    naByLevelItems: naByLevel,
    /** 已判定（进入结论统计）的项数：严重 + 警告 + 合规 */
    assessed: assessed.length,
    /** 结论分布占比用的分母（= assessed；不适用与未取到不计入） */
    compliance: complianceMatrix(results, ctx.complianceLevel),
    openItems: results.filter((r) => r.level === 'unknown'),
    /** 不映射到等保条款、只作加固参考的项 */
    hardeningItems: results.filter((r) => (r.hardening ?? null) !== null && !(r.compliance ?? []).length),
    domains: DOMAINS,
  };
}

/**
 * 前置条件层（版本前提 → 权限前提 → 依赖查询）。返回 null 表示可以执行 judge。
 *
 * 单独抽出来是因为**级别闸门**也要用它：即使某项在本级不适用，只要数据拿得到，
 * 仍然把技术结论作为参考附上 —— 升级到高等级时这份结论可直接复用。
 */
function preconditions(item, ctx, grantedPrivs) {
  if (item.edition === 'secure' && !ctx.shape.secure) {
    return {
      level: 'na',
      message: `本实例未检测到安全版能力信号（${ctx.shape.secureSignals.length ? ctx.shape.secureSignals.join('；') : '既无 PRIV_FLAG 参数、也无 MAC 字典对象'}），该项不适用。`,
    };
  }
  // 主机侧检查（os 域）不要求库权限：`priv === null` 表示「走 SSH，不看数据库账号」。
  if (item.priv !== null && !grantedPrivs.has(item.priv ?? 'SYSDBA')) {
    return { level: 'unknown', message: `需要 ${item.priv} 权限才能取得数据，本次评估未提供该账号。` };
  }
  for (const key of item.needs ?? []) {
    const err = ctx.errorOf(key);
    if (err) {
      return { level: 'unknown', message: `依赖的查询 \`${key}\` 未取到数据：${err}` };
    }
  }
  return null;
}

/** 算一次技术结论（异常一律收敛成 unknown，绝不外抛）。 */
function technicalOutcome(item, ctx, grantedPrivs) {
  const pre = preconditions(item, ctx, grantedPrivs);
  if (pre) return pre;
  try {
    const out = item.judge(ctx);
    if (!out || !out.level) return { level: 'unknown', message: '检查项未给出结论（实现缺陷）' };
    if (!out.message) return { ...out, message: '(无说明)' };
    return out;
  } catch (e) {
    return { level: 'unknown', message: `检查项执行失败：${String(e?.message ?? e)}` };
  }
}

/**
 * 级别闸门：**高等级专属条款在当前对照级别下判「不适用」**。
 *
 * ★ 为什么判 na 而不是照旧判 crit/warn：等保测评就是按你定级的那一级给结论 ——
 *   二级系统的测评项里根本没有「双因素」这一条，报「不符合」等于凭空扣分。
 * ★ 为什么还要附技术结论：na 一旦被读成「没问题」就丢了真实风险，所以原结论、证据与
 *   整改建议全部保留（items / evidence / advice），并写明「按第 N 级口径是 X」。
 * ★ `levelApplicability: 'below-level'` 是给报告用的标记：与「普通版没有这个能力」导致的
 *   na 区分开 —— 两者都判不适用，但原因完全不同。
 */
function levelGate(item, ctx, grantedPrivs) {
  const ids = item.compliance ?? [];
  const minLevel = minLevelOf(ids);
  const cur = ctx.complianceLevel;
  if (cur >= minLevel) return null;
  const ref = technicalOutcome(item, ctx, grantedPrivs);
  const ctl = ids.map((i) => parseControl(i, cur)).filter(Boolean);
  const items = [
    `本条为**第 ${minLevel} 级（${levelMeta(minLevel).label}）及以上**要求，本次按第 ${cur} 级（${levelMeta(cur).label}）对照 → 判「不适用」。`,
  ];
  if (ctl.length) {
    const higher = ctl.map((p) => parseControl(p.id, minLevel)?.id ?? p.id);
    items.push(`映射条款：本级编号 ${ctl.map((p) => p.id).join('、')}；第 ${minLevel} 级编号 ${higher.join('、')}`);
  }
  items.push(`技术结论（按第 ${minLevel} 级口径）：${LEVEL_LABEL[ref.level] ?? ref.level} —— ${String(ref.message ?? '').replace(/\*\*/g, '')}`);
  for (const extra of ref.items ?? []) items.push(extra);
  return {
    level: 'na',
    /** 报告与统计据此区分「级别差异」与「产品形态」两种不适用 */
    levelApplicability: 'below-level',
    minLevel,
    message: `本项为第 ${minLevel} 级及以上要求，本次按第 ${cur} 级对照，判「不适用」；对应技术结论见下（升级到第 ${minLevel} 级时可直接复用）。`,
    items,
    evidence: ref.evidence ?? null,
    advice: ref.advice ?? item.advice ?? null,
    /** 原级别下的结论：na 只代表「本级不要求」，不代表「已合规」 */
    originalLevel: ref.level,
  };
}

/** 单项判定。任何异常都收敛成 unknown + 原因，绝不让一项失败带走整份报告。 */
function judgeOne(item, ctx, grantedPrivs) {
  // 级别闸门放最前：本级根本没有这条要求时，「不适用」比「未取到 / 不合规」都更准确
  const gate = levelGate(item, ctx, grantedPrivs);
  if (gate) return gate;
  return technicalOutcome(item, ctx, grantedPrivs);
}

/**
 * 条款级「符合性」判定 —— 归纳成**等保测评的结论口径**。
 *
 * 为什么要单独做这一层：报告逐项给的是六态（严重/警告/提示/合规/不适用/未取到），
 * 但「这条要求我到底满足没有」是**条款级**问题 —— 一条要求常对应多个检查项，
 * 读者不该自己去数「1 个严重 + 2 个合规」算不算符合。
 *
 * 判定规则（**保守**：没有证据就不说符合）：
 *
 * | 该条款下的检查项 | 符合性 | 为什么 |
 * |---|---|---|
 * | 有「严重」 | **不符合** | 硬性要求被违反 |
 * | 无严重、有「警告」 | **部分符合** | 有可收敛的偏离，需整改 |
 * | 无严重/警告，有「合规」且无「未取到」 | **符合** | 已核对到的项都满足 |
 * | 无严重/警告，有「合规」但也有「未取到」 | **部分符合** | 已核对项满足，但证据不全 → 不敢说符合 |
 * | 只有「未取到」（无合规） | **无法判定** | 数据没拿到，既不能说符合也不能说不符合 |
 * | 只有「不适用」 | **不适用** | 产品形态（普通版无 MAC 等）或级别差异 |
 * | 只有「提示」 | **无法判定** | 「提示」只是陈述事实（如「补丁需人工核对」），**不构成合规证据** |
 *
 * ⚠️ 这仍然**不是测评结论**：它只归纳本插件能自证的范围，正式判定以测评机构现场核查为准。
 */
export const CONFORMITY_ORDER = ['fail', 'partial', 'pass', 'na', 'pending'];
export const CONFORMITY_LABEL = {
  pass: '符合',
  partial: '部分符合',
  fail: '不符合',
  na: '不适用',
  pending: '无法判定',
};

export function judgeConformity(items) {
  const list = items ?? [];
  const n = (lv) => list.filter((i) => i.level === lv).length;
  const crit = n('crit');
  const warn = n('warn');
  const ok = n('ok');
  const info = n('info');
  const unknown = n('unknown');
  const na = n('na');
  const detail = { crit, warn, ok, info, unknown, na, total: list.length };
  const L = CONFORMITY_LABEL;
  if (!list.length) return { key: 'pending', label: L.pending, reason: '该条款下没有检查项', detail };
  if (crit) {
    return {
      key: 'fail',
      label: L.fail,
      reason: `${crit} 项严重` + (warn ? `、${warn} 项警告` : '') + (unknown ? `，另有 ${unknown} 项未取到` : ''),
      detail,
    };
  }
  if (warn) {
    return {
      key: 'partial',
      label: L.partial,
      reason: `${warn} 项警告需整改` + (ok ? `（${ok} 项已合规）` : '') + (unknown ? `，另有 ${unknown} 项未取到` : ''),
      detail,
    };
  }
  if (ok && !unknown) {
    return {
      key: 'pass',
      label: L.pass,
      reason: `${ok} 项已核对且合规` + (info ? `，另有 ${info} 项提示（不构成不符合）` : ''),
      detail,
    };
  }
  if (ok && unknown) {
    return { key: 'partial', label: L.partial, reason: `已核对的 ${ok} 项合规，但有 ${unknown} 项未取到 —— 证据不全，不能判「符合」`, detail };
  }
  if (unknown) return { key: 'pending', label: L.pending, reason: `全部 ${unknown} 项未取到，数据不足`, detail };
  if (na && !info) return { key: 'na', label: L.na, reason: `${na} 项不适用（产品形态或级别差异）`, detail };
  return { key: 'pending', label: L.pending, reason: `只有 ${info} 项提示、没有合规证据 —— 「提示」不构成符合的依据`, detail };
}

/**
 * 控制点 ↔ 检查项 ↔ 结论 的映射矩阵。
 * 条款编号按**当前对照级别**重写（二级 7.1.4.x / 三级 8.1.4.x / 四级 9.1.4.x）。
 */
export function complianceMatrix(results, level = DEFAULT_COMPLIANCE_LEVEL) {
  const lv = normalizeLevel(level);
  const byControl = new Map();
  for (const r of results) {
    for (const c of r.compliance) {
      if (!byControl.has(c)) byControl.set(c, []);
      byControl.get(c).push(r);
    }
  }
  return [...byControl.entries()]
    .map(([control, items]) => {
      const worst = LEVEL_ORDER.find((x) => items.some((i) => i.level === x)) ?? 'info';
      // 带上章条标题与要求**摘要**（见 compliance.js 的说明：摘要是为了便于阅读，不是标准原文）
      const p = parseControl(control, lv);
      const minLevel = minLevelOf([control]);
      return {
        control: p?.id ?? control,
        /** checks.js 里的规范写法（第三级编号），便于回查代码 */
        sourceControl: control,
        items,
        worst,
        count: items.length,
        title: p?.title ?? null,
        requirement: p?.requirement ?? null,
        order: p?.order ?? 99,
        letter: p?.letter ?? '',
        minLevel,
        applicable: lv >= minLevel,
        /** 该控制点下所有项都是「本级不要求」导致的 na */
        notApplicableByLevel: items.length > 0 && items.every((i) => i.levelApplicability === 'below-level'),
        /** ★ 条款级符合性（等保测评口径）：符合 / 部分符合 / 不符合 / 不适用 / 无法判定 */
        conformity: judgeConformity(items),
      };
    })
    .sort((a, b) => a.control.localeCompare(b.control, 'zh-Hans-CN', { numeric: true }));
}

/** 条款级符合性的分布（报告「等保对照」一节的看板与文本结论都用它）。 */
export function conformityCounts(matrix) {
  const out = Object.fromEntries(CONFORMITY_ORDER.map((k) => [k, 0]));
  for (const c of matrix ?? []) {
    const k = c.conformity?.key ?? 'pending';
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

/** 「最要紧的几件事」：按 严重→警告 排序，同级按权重与域顺序。 */
export function topActions(results, n = 8) {
  const rank = { crit: 0, warn: 1 };
  return results
    .filter((r) => r.level === 'crit' || r.level === 'warn')
    .sort((a, b) => (rank[a.level] - rank[b.level]) || (b.weight - a.weight))
    .slice(0, n);
}
