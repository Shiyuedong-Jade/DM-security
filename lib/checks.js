/**
 * 达梦安全评估 —— 检查项目录（与 DESIGN.md §4 的表格一一对应）。
 *
 * 每个检查项：
 *   id          域.项，与 DESIGN 表格一致（smoke.mjs 会断言集合完全相同，防文档与代码漂移）
 *   domain      所属域（DOMAINS 的 key）
 *   title       中文名
 *   level       **该项可能给出的最重结论**（只用于「最要紧的几件事」排序：crit=10 / warn=4 / info=1；不参与任何计分）
 *   priv        取数所需的最小权限；调用方未提供该账号时判 unknown
 *   edition     'secure' 表示仅安全版适用，不满足则判 na
 *   needs       依赖的查询 key；任一查询没取到 → unknown（带原因）
 *   compliance  等保 2.0「安全计算环境」控制点（工作基线，见 DESIGN §8#9）。
 *               **本文件里按第三级编号书写**（与标准原文一致）；渲染与判定时由
 *               `parseControl(id, level)` 按当前对照级别重写成 7.1.4.x / 8.1.4.x / 9.1.4.x，
 *               并按条款的 `minLevel` 决定本级是否适用（见 DESIGN §2.5）。
 *   judge(ctx)  → { level, message, advice?, evidence? }
 *
 * `judge` 的返回值里 **message 必填**：`na` 与 `unknown` 都必须说清原因。
 *
 * ⚠️ 本文件的多处口径由 **2026-10-12 在 10.0.0.40（DM8 企业版 8.1.3，单实例）真机核对**修正，
 *    凡带「真机」字样的注释都是那次跑出来的实测结论，不要按文档想当然改回去。
 */

import { col, num, isBuiltin, fmtList, truthy } from './util.js';

export const DOMAINS = [
  { key: 'ident', title: '身份鉴别', order: 1 },
  { key: 'auth', title: '认证方式与登录控制', order: 2 },
  { key: 'pwd', title: '口令策略', order: 3 },
  { key: 'dac', title: '自主访问控制', order: 4 },
  { key: 'sod', title: '职责分离', order: 5 },
  { key: 'mac', title: '强制访问控制', order: 6 },
  { key: 'audit', title: '安全审计', order: 7 },
  { key: 'comm', title: '通信安全', order: 8 },
  { key: 'enc', title: '存储加密', order: 9 },
  { key: 'res', title: '资源限制', order: 10 },
  { key: 'net', title: '访问路径', order: 11 },
  { key: 'expo', title: '暴露面与代码安全', order: 12 },
  { key: 'os', title: '主机侧（OS / SSH）', order: 13 },
];

const up = (v) => String(v ?? '').trim().toUpperCase();
const R = (level, message, extra = {}) => ({ level, message, ...extra });

/**
 * 达梦家族的**服务端**监听进程 —— DMDSC 上一台主机会同时出现多个。
 *
 * 为什么需要：`os.listen_binding` 原来只判**数据库端口**。单实例上够用（只有 `dmserver`），
 * 但 DMDSC 上同一台主机还跑着集群同步（`dmcss`）、ASM 服务（`dmasmsvrm`）、助手进程（`dmap`），
 * 它们各自占一个端口、同样可能对全网卡开放 —— 那正是「关闭不需要的服务 / 高危端口」要管的。
 * 真机实测 `10.0.0.61`：7236/7336 `dmserver`、7436/7536 `dmasmsvrm`、7936 `dmcss`、4236 `dmap`，全部绑 `*`。
 */
const DM_LISTEN_PROC = /^(dmserver|dmcss|dmasmsvrm|dmap|dmwatcher)$/i;
const DM_LISTEN_ROLE = {
  dmserver: '数据库实例',
  dmcss: 'DMDSC 集群同步',
  dmasmsvrm: 'ASM 服务',
  dmap: '达梦助手进程',
  dmwatcher: '数据守护 watcher',
};
/** 「绑到所有网卡」的地址形态（`ss` 会给出裸 `*`）。 */
const WILDCARD_ADDR = /^(0\.0\.0\.0|\*|::|\[::\])$/;

/** 达梦 PWD_POLICY 位掩码含义（31 = 五条全要）。真机验证：PWD_POLICY=15 时缺的正是 bit16「标点符号」。 */
const PWD_BITS = [
  [1, '禁止与用户名相同'],
  [2, '口令长度不小于 9'],
  [4, '至少一个大写字母'],
  [8, '至少一个数字'],
  [16, '至少一个标点符号'],
];
function decodePwdPolicy(v) {
  const n = num(v);
  if (n === null) return [];
  return PWD_BITS.filter(([bit]) => (n & bit) === bit).map(([, t]) => t);
}

/** IP 脱敏：报告默认不暴露客户端完整地址（DESIGN §1.2#5）。 */
function maskIp(ip) {
  const s = String(ip ?? '').trim();
  if (!s) return '(本机/未知)';
  if (s.startsWith('::')) return `(本机/IPv6 ${s.slice(0, 6)}…)`;
  const parts = s.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
  return s.length > 8 ? `${s.slice(0, 4)}***` : s;
}

const notBuiltin = (name) => !isBuiltin(name);

/** 距今天数（用于账号休眠判定）。解析不了返回 null。 */
function daysSince(stamp) {
  const s = String(stamp ?? '').trim();
  if (!s) return null;
  const t = Date.parse(s.replace(' ', 'T'));
  if (!Number.isFinite(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}

/** 系统属主：这些属主下的对象权限授予 PUBLIC 属达梦默认（真机实测 236 条里 236 条都是系统对象）。 */
const SYSTEM_OWNERS = ['SYS', 'SYSDBA', 'SYSSSO', 'SYSAUDITOR', 'SYSDBO', 'SYSJOB', 'CTISYS', 'SYSTEM'];

/** 内置角色名单。真机实测的本版本内置角色已全部列入（避免把内置角色报成「自定义角色」）。 */
export const KNOWN_ROLES = [
  'DBA', 'PUBLIC', 'RESOURCE', 'SOI', 'VTI', 'SVI', 'SYS_ADMIN', 'SELECT_CATALOG_ROLE', 'OLAP',
  'DB_AUDIT_ADMIN', 'DB_AUDIT_OPER', 'DB_AUDIT_PUBLIC', 'DB_AUDIT_SELECT_CATALOG_ROLE',
  'DB_AUDIT_SOI', 'DB_AUDIT_SVI', 'DB_AUDIT_VTI',
  'DB_POLICY_ADMIN', 'DB_POLICY_OPER', 'DB_POLICY_PUBLIC', 'DB_POLICY_SELECT_CATALOG_ROLE',
  'DB_POLICY_SOI', 'DB_POLICY_SVI', 'DB_POLICY_VTI',
  'DB_OBJECT_ADMIN', 'DB_DBA', 'SYSDBA', 'SYSAUDITOR', 'SYSSSO', 'SYSDBO', 'SYS',
];

/**
 * PUBLIC 上的**数据库级**高危系统权限。
 *
 * ⚠️ 真机校准：达梦默认就给 PUBLIC 48 项权限（ALTER TABLE / DROP TABLE / EXECUTE PACKAGE /
 * GRANT SCHEMA / DUMP TABLE …），这些是**对象类**权限（只在自己有权的对象上生效），属产品默认。
 * 原来把「PUBLIC 有系统权限」一律判警告，真机上会直接误报 48 条。
 * 这里只盯真正越界的：账号管理、库级管理、ANY 类、GRANT ANY。
 */
/**
 * PROFILE 资源项的中文注解。
 * 报告里直接甩 `DEFAULT.CPU_PER_SESSION` 这种英文键对读者不友好；这些名字来自真机
 * `SELECT PROFILE, RESOURCE_NAME, RESOURCE_TYPE, LIMIT FROM DBA_PROFILES`（2026-10-12，14 行）。
 */
const PROFILE_RESOURCE_LABEL = {
  CONNECT_IDLE_TIME: '连接空闲超时',
  CONNECT_TIME: '单次连接总时长',
  CPU_PER_CALL: '单次调用 CPU 时间',
  CPU_PER_SESSION: '单会话 CPU 时间',
  MEM_SPACE: '单用户内存上限',
  READ_PER_CALL: '单次调用读取量',
  READ_PER_SESSION: '单会话读取量',
  SESSION_PER_USER: '单用户并发会话数',
  PASSWORD_LIFE_TIME: '口令有效期',
  PASSWORD_REUSE_MAX: '口令重用次数',
  PASSWORD_REUSE_TIME: '口令重用时间窗',
  PASSWORD_LOCK_TIME: '口令锁定时长',
  FAILED_LOGIN_ATTEMPTS: '登录失败锁定次数',
  PASSWORD_GRACE_TIME: '口令到期宽限期',
};

/** 把 `DEFAULT.CPU_PER_SESSION` 渲染成 `DEFAULT.CPU_PER_SESSION（单会话 CPU 时间）`。 */
function profileLabel(full) {
  const s = String(full);
  const zh = PROFILE_RESOURCE_LABEL[up(s.split('.').pop())];
  return zh ? `${s}（${zh}）` : s;
}

/** 危险包/过程的用途归类（**按名称归类，未逐一实测其能力**，故只写「类」）。 */
const DANGEROUS_LABEL = {
  UTL_FILE: '文件读写类',
  DBMS_LOB: '大对象操作类',
  DBMS_SQL: '动态 SQL 类',
  DBMS_UTILITY: '系统工具类',
  DBMS_XMLGEN: 'XML 生成类',
  DBMS_LOCK: '锁与等待类',
  DBMS_SCHEDULER: '作业调度类',
  DBMS_PIPE: '进程间管道类',
  DBMS_JAVA: 'Java 过程类',
  JAVA: 'Java 源类',
  SP_CREATE_JOB: '创建作业',
  SP_FILE_SQL: '从文件执行 SQL',
};

/** `SYS.UTL_FILE（文件读写类）` 形式的注解；名册外的对象只给原名。 */
function dangerousLabel(owner, name) {
  const zh = DANGEROUS_LABEL[up(name)];
  return `${owner}.${name}${zh ? `（${zh}）` : ''}`;
}

const PUBLIC_RISKY_PRIV =
  /^(CREATE|ALTER|DROP)\s+USER$|^(CREATE|ALTER|DROP)\s+DATABASE$|^ALTER\s+SYSTEM$|^BACKUP\s+DATABASE$|^RESTORE\s+DATABASE$|^GRANT\s+ANY|^DROP\s+ANY|^CREATE\s+ANY|^ALTER\s+ANY|^SELECT\s+ANY|^EXECUTE\s+ANY|^INSERT\s+ANY|^UPDATE\s+ANY|^DELETE\s+ANY/i;

/**
 * 「逐账号取不到就退回 DEFAULT profile」的取值口径。
 *
 * 真机实测：`SYSUSERS.FAILED_NUM=0` 而 `DBA_PROFILES.DEFAULT.FAILED_LOGIN_ATTEMPTS=3` ——
 * 逐账号列是**覆盖值**（0 = 未覆盖），profile 才是生效的默认。判「未设置失败锁定」之前
 * 必须先看 profile，否则会把一个配了 3 次的库报成「可无限次尝试口令」。
 */
function effectiveLimit(c, rowField, rowValue, profileResource) {
  const prof = profileResource ? c.prof(profileResource) : null;
  if (rowValue !== null && rowValue !== undefined && rowValue > 0) {
    return { value: rowValue, source: '逐账号', unlimited: false };
  }
  if (prof) {
    if (prof.unlimited) return { value: null, source: 'DEFAULT profile', unlimited: true };
    const n = num(prof.value);
    if (n !== null) return { value: n, source: 'DEFAULT profile', unlimited: false };
  }
  return { value: null, source: '未取到', unlimited: false };
}

/**
 * 账号级访问路径控制的**统一取数源**。
 *
 * 真机结论：这两个控制项在 `SYSUSERS`（ALLOW_ADDR / NOT_ALLOW_ADDR / ALLOW_DT）。
 * 但不同版本/权限下 `userAccess` 那条查询可能降级甚至失败，而 `pwdPolicy` 查的是同一张表，
 * 所以两边任一有该列就用它 —— 避免出现「pwdPolicy 里明明有 ALLOW_ADDR，却因为
 * userAccess 降级了就把 IP 白名单判成未取到」。
 */
function accessSource(c) {
  if (c.pwd.accessColumnPresent && c.pwd.rows.length) {
    return {
      src: 'SYSUSERS（pwdPolicy 查询）',
      rows: c.pwd.rows.map((r) => ({ name: r.name, allow: r.allowAddr, deny: r.notAllowAddr, dt: r.allowDt })),
    };
  }
  const ua = c.rows('userAccess');
  if (ua.length && (c.hasCol(ua[0], 'ALLOW_ADDR') || c.hasCol(ua[0], 'ALLOW_IP'))) {
    return {
      src: 'userAccess 查询',
      rows: ua.map((r) => ({
        name: col(r, 'USERNAME'),
        allow: col(r, 'ALLOW_ADDR', 'ALLOW_IP'),
        deny: col(r, 'NOT_ALLOW_ADDR', 'NOT_ALLOW_IP'),
        dt: col(r, 'ALLOW_DT', 'ALLOW_DATETIME'),
      })),
    };
  }
  return null;
}

export const CHECKS = [
  // ==================================================== A 身份鉴别
  {
    id: 'ident.admin_accounts',
    domain: 'ident',
    title: '管理员账号状态与属性',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['users'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const admins = c.admins();
      const evidence = admins.map((a) => ({
        账号: a.name,
        是否存在: a.user ? '存在' : '不存在',
        状态: a.user?.status || '—',
        认证方式: a.user?.authType || '—',
        锁定时间: a.user?.lockDate || '—',
        过期时间: a.user?.expiryDate || '—',
      }));
      const sysdba = admins.find((a) => a.name === 'SYSDBA');
      if (!sysdba?.user) return R('crit', '数据库中不存在 SYSDBA 账号 —— 请确认评估连接的是否为达梦实例。', { evidence });
      if (sysdba.user.status && sysdba.user.status !== 'OPEN') {
        return R('crit', `数据库管理员账号 SYSDBA 当前状态为 ${sysdba.user.status}，不可用。`, { evidence });
      }
      const notOpen = admins.filter((a) => a.user && a.user.status && a.user.status !== 'OPEN' && a.name !== 'SYSDBA');
      if (notOpen.length) {
        const names = notOpen.map((a) => `${a.name}(${a.user.status})`).join('、');
        if (c.shape.secure) {
          return R('warn', `安全版实例中有管理员账号不可用：${names}。职责分离需要各管理员账号都能实际登录。`, { evidence });
        }
        return R(
          'info',
          `SYSDBA 状态正常；另有 ${names} 未启用。${c.shape.edition ?? '普通版'}不提供安全员/审计员的职责分离配置，` +
            '这些账号默认不可用属安装默认值；若贵司按三权分立运维，请确认是否需要启用。',
          { evidence },
        );
      }
      return R('ok', `已核对 ${admins.length} 个管理员账号，状态均正常（${c.shape.privMode ?? `${c.shape.edition ?? '普通版'}，无分立配置`}）。`, { evidence });
    },
    advice: '管理员账号应由不同人员保管；离职/交接后立即改密并核对账号状态。',
  },
  {
    id: 'ident.locked_expired',
    domain: 'ident',
    title: '业务账号锁定与过期',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['users'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const biz = c.biz();
      if (!biz.length) {
        return R(
          'info',
          `本库共 ${c.users.length} 个账号，**全部是内置账号或采集账号**（${fmtList(c.users.map((u) => u.name))}），没有业务账号，本项无可判定对象。`,
          { evidence: c.users.map((u) => ({ 账号: u.name, 状态: u.status || '—', 类别: '内置/采集' })) },
        );
      }
      const evidence = biz.map((u) => ({ 账号: u.name, 状态: u.status || '—', 锁定时间: u.lockDate || '—', 过期时间: u.expiryDate || '—' }));
      const expired = biz.filter((u) => u.status.includes('EXPIRED'));
      const locked = biz.filter((u) => u.status.includes('LOCKED') && !u.status.includes('EXPIRED'));
      if (expired.length) return R('crit', `有 ${expired.length} 个业务账号已过期：${fmtList(expired.map((u) => u.name))}。过期账号与残留权限常被忽视。`, { evidence });
      if (locked.length) return R('warn', `有 ${locked.length} 个业务账号处于锁定状态：${fmtList(locked.map((u) => u.name))}。请确认是失败锁定还是已停用。`, { evidence });
      return R('ok', `共 ${biz.length} 个业务账号，状态均正常（无锁定、无过期）。`, { evidence });
    },
  },
  {
    // ★ 真机新增（DESIGN 原为 P1）：SYSUSERS.LAST_LOGIN_DTID / LAST_LOGIN_IP 实测存在，
    //   账号休眠期因此从「做不到」变成「可判定」。
    id: 'ident.dormant_accounts',
    domain: 'ident',
    title: '长期未登录 / 从未登录的账号',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      if (!c.pwd.lastLoginColumnPresent) {
        return R('unknown', '本版本的 `SYSUSERS` 未暴露 `LAST_LOGIN_DTID` 列（降级查询生效），无法判断账号休眠情况；请人工核对 `SELECT USERNAME, LAST_LOGIN_DTID, LAST_LOGIN_IP FROM SYSUSERS`。');
      }
      const biz = c.bizPwd();
      const evidence = c.pwd.rows.map((r) => ({
        账号: r.name,
        最近登录: r.lastLogin || '从未登录',
        最近登录IP: r.lastLoginIp ? maskIp(r.lastLoginIp) : '—',
        类别: r.builtin ? '内置/采集' : '业务',
      }));
      if (!biz.length) {
        return R('info', `本库没有业务账号，无可判定的休眠对象；${c.pwd.rows.length} 个内置/采集账号的最近登录时间见证据。`, { evidence });
      }
      const never = biz.filter((r) => !r.lastLogin);
      const stale = biz.filter((r) => {
        const d = daysSince(r.lastLogin);
        return d !== null && d > c.th.dormantDays;
      });
      if (never.length) {
        return R('warn', `有 ${never.length} 个业务账号**从未登录过**：多为交付后遗留的空账号，应收敛或删除。`, {
          items: never.map((r) => `账号 ${r.name}（从未登录）`),
          advice: '清理从未使用/长期未使用的账号；确需保留的应锁定（ACCOUNT LOCK）并记录用途。',
          evidence,
        });
      }
      if (stale.length) {
        return R('warn', `有 ${stale.length} 个业务账号超过 ${c.th.dormantDays} 天未登录：${fmtList(stale.map((r) => r.name))}。`, {
          advice: '确认是否仍在使用；停用账号应及时锁定并回收权限。',
          evidence,
        });
      }
      return R('ok', `共 ${biz.length} 个业务账号，最近登录时间均在 ${c.th.dormantDays} 天内。`, { evidence });
    },
  },
  {
    id: 'ident.os_auth_accounts',
    domain: 'ident',
    title: '走 OS / 外部认证的账号',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['users'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const withAuth = c.users.filter((u) => u.authType);
      if (!withAuth.length) {
        return R('unknown', '本版本 `DBA_USERS` 未提供 `AUTHENTICATION_TYPE` 列（降级查询生效），无法判断账号的认证方式；请人工核对各账号的认证配置。');
      }
      // 真机实测：数据库口令认证的取值是 `NDCT_DB_AUTHENT`（不是文档里的中文描述）
      const isDbAuth = (t) => /DB_AUTHENT|DATABASE|数据库/i.test(t);
      const external = withAuth.filter((u) => !isDbAuth(u.authType));
      const evidence = withAuth.map((u) => ({ 账号: u.name, 认证方式: u.authType, 内置: u.builtin ? '是' : '否' }));
      if (!external.length) return R('ok', `共 ${withAuth.length} 个账号，认证方式均为数据库口令认证（${fmtList(withAuth.map((u) => u.authType))}）。`, { evidence });
      const biz = external.filter((u) => !u.builtin);
      const msg =
        `有 ${external.length} 个账号使用数据库口令以外的认证方式：` +
        external.map((u) => `${u.name}(${u.authType})`).join('、') +
        '。OS / 外部认证绕过数据库口令策略，需确认其边界与来源限制。';
      return biz.length
        ? R('warn', msg, { evidence, advice: '对走 OS / 外部认证的账号设置来源 IP 限制，或改为数据库口令 + 强策略。' })
        : R('info', msg + '（均为内置管理员账号，属部署选择）', { evidence });
    },
  },
  {
    id: 'ident.builtin_inventory',
    domain: 'ident',
    title: '内置账号清单',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['users'],
    compliance: ['8.1.4.2(b)'],
    judge(c) {
      const present = c.users.filter((u) => u.builtin);
      // 真机纠正：安全员是 SYSSSO（三个 S），不是 SYSSO
      const expected = ['SYS', 'SYSDBA', 'SYSSSO', 'SYSAUDITOR'];
      const evidence = expected.map((n) => ({
        账号: n,
        是否在库: present.some((u) => u.name.toUpperCase() === n) ? '是' : '否',
        状态: present.find((u) => u.name.toUpperCase() === n)?.status || '—',
      }));
      const extra = present.filter((u) => !expected.includes(u.name.toUpperCase())).map((u) => u.name);
      return R(
        'info',
        `内置账号实测存在 ${present.length} 个：${fmtList(present.map((u) => u.name))}。` +
          (extra.length ? `其中 ${fmtList(extra)} 属采集类账号（如 AWR），一并在白名单内。` : '') +
          '内置账号的默认状态（口令永不过期、无资源限制）不计为缺陷，但应改默认口令后按贵司规范单独评估。',
        { evidence },
      );
    },
    advice: '安装后立即修改 SYSDBA/SYSSSO/SYSAUDITOR 的默认口令，并确认各账号由不同人员保管。',
  },

  // ==================================================== B 认证方式
  {
    id: 'auth.local_osauth',
    domain: 'auth',
    title: '本地操作系统认证',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const p = c.p('ENABLE_LOCAL_OSAUTH');
      if (!p) return R('na', '本版本参数表中不存在 `ENABLE_LOCAL_OSAUTH`，该版本不提供本地 OS 认证开关。');
      if (truthy(p.value)) {
        const changed = String(p.def ?? '0') !== '1';
        return R('warn', `本地 OS 认证已开启（ENABLE_LOCAL_OSAUTH=${p.value}${changed ? `，默认值为 ${p.def}` : ''}）：服务器上具备 OS 权限的账号可绕过数据库口令直接登录。`, {
          advice: '确认确实需要 OS 认证；否则置 ENABLE_LOCAL_OSAUTH=0。',
          evidence: [{ 参数: 'ENABLE_LOCAL_OSAUTH', 当前值: String(p.value), 默认值: String(p.def ?? '—') }],
        });
      }
      return R('ok', `本地 OS 认证未开启（ENABLE_LOCAL_OSAUTH=${p.value}）。`);
    },
  },
  {
    id: 'auth.remote_osauth',
    domain: 'auth',
    title: '远程操作系统认证',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const p = c.p('ENABLE_REMOTE_OSAUTH');
      if (!p) return R('na', '本版本参数表中不存在 `ENABLE_REMOTE_OSAUTH`，该版本不提供远程 OS 认证开关。');
      if (truthy(p.value)) {
        return R('crit', `远程 OS 认证已开启（ENABLE_REMOTE_OSAUTH=${p.value}）：远端主机可凭 OS 身份登录数据库，绕过全部口令策略与 IP 限制。`, {
          advice: '生产环境应关闭远程 OS 认证（ENABLE_REMOTE_OSAUTH=0）；如确需使用，必须配合网络层访问控制。',
          evidence: [{ 参数: 'ENABLE_REMOTE_OSAUTH', 当前值: String(p.value), 默认值: String(p.def ?? '—') }],
        });
      }
      return R('ok', `远程 OS 认证未开启（ENABLE_REMOTE_OSAUTH=${p.value}）。`);
    },
  },
  {
    id: 'auth.external_provider',
    domain: 'auth',
    title: '外部认证配置痕迹',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const hits = [];
      for (const p of c.params.values()) {
        if (/LDAP|KERBER|RADIUS|SSL|UKEY/i.test(p.name)) hits.push({ 参数: p.name, 当前值: String(p.value ?? ''), 说明: String(p.desc ?? '').slice(0, 60) });
      }
      const authTypes = [...new Set(c.users.map((u) => u.authType).filter(Boolean))];
      const evidence = [...hits.slice(0, 20), ...authTypes.map((t) => ({ 参数: '（账号认证方式）', 当前值: t, 说明: '' }))];
      if (!hits.length) {
        return R('info', `参数表中未发现 LDAP / KERBEROS / RADIUS / SSL 等外部认证参数；账号认证方式实测为：${authTypes.join('、') || '(未取到)'}。`);
      }
      return R('info', `发现 ${hits.length} 个外部认证相关参数（见证据）。外部统一认证通常优于库内口令，但需确认其信任链与来源限制。`, { evidence });
    },
  },
  {
    id: 'auth.ip_whitelist',
    domain: 'auth',
    title: '账号级 IP 白/黑名单',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.4(c)'],
    judge(c) {
      const src = accessSource(c);
      if (!src) {
        return R(
          'unknown',
          '本版本的 `SYSUSERS` 与 `DBA_USERS` 都未暴露 IP 白/黑名单列（降级查询生效）。' +
            '请人工核对：`SELECT d.USERNAME, s.ALLOW_ADDR, s.NOT_ALLOW_ADDR FROM SYSUSERS s, DBA_USERS d WHERE s.ID = d.USER_ID`。',
        );
      }
      const configured = src.rows.filter((r) => r.allow || r.deny);
      const evidence = src.rows.map((r) => ({ 账号: r.name, 允许: r.allow ?? '—', 禁止: r.deny ?? '—' }));
      if (!configured.length) {
        return R('warn', `共 ${src.rows.length} 个账号，**没有任何账号配置 IP 白名单或黑名单**：口令泄露后可从任意网络位置登录。`, {
          advice: '对重要业务账号与管理员账号设置允许来源地址（`ALTER USER ... ALLOW_IP`），或限制监听网段。',
          evidence,
        });
      }
      return R('ok', `共 ${src.rows.length} 个账号，其中 ${configured.length} 个配置了 IP 白/黑名单（数据源：${src.src}）。`, {
        evidence: configured.map((r) => ({ 账号: r.name, 允许: r.allow ?? '—', 禁止: r.deny ?? '—' })),
      });
    },
  },
  {
    id: 'auth.login_window',
    domain: 'auth',
    title: '账号级登录时间段限制',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.4(c)'],
    judge(c) {
      const src = accessSource(c);
      if (!src) return R('unknown', '本版本未在 `SYSUSERS`/`DBA_USERS` 暴露登录时间段列（降级查询生效），需人工核对。');
      const configured = src.rows.filter((r) => r.dt);
      if (!configured.length) {
        return R('info', `共 ${src.rows.length} 个账号均未限制登录时间段。该项属可选加固：对只在固定时段使用的批处理账号可以设置。`);
      }
      return R('info', `${configured.length} 个账号设置了登录时间段限制。`, {
        evidence: configured.map((r) => ({ 账号: r.name, 允许时间段: String(r.dt).slice(0, 80) })),
      });
    },
  },

  // ==================================================== C 口令策略
  {
    id: 'pwd.global_policy',
    domain: 'pwd',
    title: '全局口令复杂度策略',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const p = c.p('PWD_POLICY');
      if (!p) return R('na', '本版本参数表中不存在 `PWD_POLICY`，无法评估口令复杂度策略。');
      const n = num(p.value);
      const on = decodePwdPolicy(p.value);
      const evidence = [{ 参数: 'PWD_POLICY', 当前值: String(p.value), 默认值: String(p.def ?? '—'), 已启用的约束: on.length ? on.join('、') : '（无）' }];
      if (n === null) return R('unknown', `PWD_POLICY 取值 \`${p.value}\` 无法解析为位掩码，需人工核对。`, { evidence });
      if (n === 0) {
        return R('crit', '口令复杂度策略未启用（PWD_POLICY=0）：任意弱口令均可设置，直接违反等保身份鉴别要求。', {
          advice: `建议设置 PWD_POLICY=${c.th.pwdPolicyMin}（禁同名 + 长度≥9 + 大写 + 数字 + 标点）。`,
          evidence,
        });
      }
      if (n < c.th.pwdPolicyMin) {
        const missing = PWD_BITS.filter(([bit]) => (n & bit) !== bit).map(([, t]) => t);
        return R('warn', `口令复杂度策略不完整（PWD_POLICY=${n}），缺少：${missing.join('、')}。`, {
          advice: `建议 PWD_POLICY=${c.th.pwdPolicyMin}。`,
          evidence,
        });
      }
      return R('ok', `口令复杂度策略已启用且完整（PWD_POLICY=${n}：${on.join('、')}）。`, { evidence });
    },
  },
  {
    id: 'pwd.min_len',
    domain: 'pwd',
    title: '口令最小长度',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      const p = c.p('PWD_MIN_LEN');
      if (!p) return R('na', '本版本参数表中不存在 `PWD_MIN_LEN`（长度约束可能由 PWD_POLICY 的位掩码控制，见「全局口令复杂度策略」）。');
      const n = num(p.value);
      const evidence = [{ 参数: 'PWD_MIN_LEN', 当前值: String(p.value), 阈值: String(c.th.pwdMinLen) }];
      if (n === null) return R('unknown', `PWD_MIN_LEN 取值 \`${p.value}\` 无法解析。`, { evidence });
      if (n < c.th.pwdMinLen) return R('warn', `口令最小长度 ${n} 小于基线 ${c.th.pwdMinLen} 位。`, { advice: `建议 PWD_MIN_LEN≥${c.th.pwdMinLen}（等保实践值常见为 8~9 位，与级别无关）。`, evidence });
      return R('ok', `口令最小长度 ${n} 位，满足基线 ${c.th.pwdMinLen} 位。`, { evidence });
    },
  },
  {
    id: 'pwd.never_expire',
    domain: 'pwd',
    title: '口令永不过期',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      if (!c.pwd.rows.length) return R('unknown', '未取到逐账号口令策略（`SYSUSERS` 与 `DBA_USERS` 关联查询无结果），需 SYSDBA 权限。');
      const profLife = c.prof('PASSWORD_LIFE_TIME');
      const profNote = profLife
        ? `DEFAULT profile 的 PASSWORD_LIFE_TIME=${profLife.raw ?? profLife.value}。`
        : '未取到 DEFAULT profile 的口令有效期配置。';
      const never = c.pwd.rows.filter((r) => r.lifeDays === 0);
      const biz = never.filter((r) => !r.builtin);
      const builtin = never.filter((r) => r.builtin);
      const evidence = c.pwd.rows.map((r) => ({ 账号: r.name, '口令有效期(天)': r.lifeDays === null ? '—' : String(r.lifeDays), 内置: r.builtin ? '是' : '否' }));
      if (biz.length) {
        return R('warn', `有 ${biz.length} 个业务账号口令永不过期（LIFE_TIME=0）。${profNote}`, {
          items: biz.map((r) => `账号 ${r.name}（LIFE_TIME=0）`),
          advice: `建议业务账号口令有效期 ≤${c.th.pwdLifeMaxDays} 天（常见 90 天）。`,
          evidence,
        });
      }
      if (builtin.length) {
        return R('info', `未发现业务账号口令永不过期；${builtin.length} 个内置账号为 0（安装默认值，不计为缺陷）。${profNote}`, {
          items: builtin.map((r) => `账号 ${r.name}（内置/采集，默认值）`),
          evidence,
        });
      }
      return R('ok', `共 ${c.pwd.rows.length} 个账号均已配置口令有效期。`, { evidence });
    },
  },
  {
    id: 'pwd.max_life',
    domain: 'pwd',
    title: '口令有效期过长',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      if (!c.pwd.rows.length) return R('unknown', '未取到逐账号口令策略，无法判断口令有效期。');
      const tooLong = c.pwd.rows.filter((r) => r.lifeDays !== null && r.lifeDays > c.th.pwdLifeMaxDays);
      if (tooLong.length) {
        return R('warn', `有 ${tooLong.length} 个账号口令有效期超过 ${c.th.pwdLifeMaxDays} 天：${fmtList(tooLong.map((r) => r.name))}。`, {
          evidence: tooLong.map((r) => ({ 账号: r.name, '口令有效期(天)': String(r.lifeDays), 阈值: String(c.th.pwdLifeMaxDays) })),
        });
      }
      return R('ok', `未发现口令有效期超过 ${c.th.pwdLifeMaxDays} 天的账号。`);
    },
  },
  {
    id: 'pwd.lock_threshold',
    domain: 'pwd',
    title: '登录失败锁定阈值',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.1(b)'],
    judge(c) {
      if (!c.pwd.rows.length) return R('unknown', '未取到逐账号口令策略，无法判断登录失败锁定阈值。');
      const targets = c.bizPwd().length ? c.bizPwd() : c.pwd.rows;
      const onlyBuiltin = c.bizPwd().length === 0;
      const rows = targets.map((r) => ({ r, eff: effectiveLimit(c, 'failedNum', r.failedNum, 'FAILED_LOGIN_ATTEMPTS') }));
      const evidence = rows.map(({ r, eff }) => ({
        账号: r.name,
        '逐账号 FAILED_NUM': r.failedNum === null ? '—' : String(r.failedNum),
        '生效阈值': eff.unlimited ? 'UNLIMITED' : eff.value === null ? '未取到' : String(eff.value),
        来源: eff.source,
        已失败次数: r.failedAttemps === null ? '—' : String(r.failedAttemps),
      }));
      if (rows.every(({ eff }) => eff.value === null && !eff.unlimited)) {
        return R('unknown', '逐账号与 DEFAULT profile 都未取到失败锁定配置，无法判断；请人工核对 `SELECT * FROM DBA_PROFILES` 的 FAILED_LOGIN_ATTEMPTS。', { evidence });
      }
      const unlimited = rows.filter(({ eff }) => eff.unlimited);
      const tooMany = rows.filter(({ eff }) => eff.value !== null && eff.value > c.th.failedLoginMax);
      const lv = onlyBuiltin ? 'info' : 'warn';
      if (unlimited.length) {
        return R(lv, `${onlyBuiltin ? '（本库无业务账号，以下为内置账号）' : ''}有 ${unlimited.length} 个账号未设置失败锁定（逐账号 FAILED_NUM=0 且 DEFAULT profile=UNLIMITED），可无限次尝试口令：${fmtList(unlimited.map(({ r }) => r.name))}。`, {
          advice: `建议失败锁定次数 ≤${c.th.failedLoginMax} 次。注意：达梦存在「已设置失败锁定但实际未生效」的已知反馈，配置后需实测验证一次。`,
          evidence,
        });
      }
      if (tooMany.length) {
        return R(lv, `${onlyBuiltin ? '（本库无业务账号，以下为内置账号）' : ''}有 ${tooMany.length} 个账号失败锁定阈值大于 ${c.th.failedLoginMax} 次：${fmtList(tooMany.map(({ r }) => r.name))}。`, { evidence });
      }
      return R('ok', `${onlyBuiltin ? '（本库无业务账号，按内置账号核对）' : ''}共 ${rows.length} 个账号的生效失败锁定阈值不超过 ${c.th.failedLoginMax} 次。`, { evidence });
    },
  },
  {
    id: 'pwd.lock_time',
    domain: 'pwd',
    title: '账号锁定时长',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.1(b)'],
    judge(c) {
      if (!c.pwd.rows.length) return R('unknown', '未取到逐账号口令策略，无法判断锁定时长。');
      const targets = c.bizPwd().length ? c.bizPwd() : c.pwd.rows;
      const onlyBuiltin = c.bizPwd().length === 0;
      const rows = targets.map((r) => ({ r, lock: effectiveLimit(c, 'lockTime', r.lockTime, 'PASSWORD_LOCK_TIME') }));
      const evidence = rows.map(({ r, lock }) => ({
        账号: r.name,
        '逐账号 LOCK_TIME': r.lockTime === null ? '—' : String(r.lockTime),
        '生效锁定': lock.unlimited ? 'UNLIMITED' : lock.value === null ? '未取到' : String(lock.value),
        来源: lock.source,
      }));
      const noLock = rows.filter(({ lock }) => !lock.unlimited && lock.value === 0);
      const unknown = rows.filter(({ lock }) => lock.value === null && !lock.unlimited);
      if (noLock.length) {
        return R(onlyBuiltin ? 'info' : 'warn', `${onlyBuiltin ? '（本库无业务账号，以下为内置账号）' : ''}有 ${noLock.length} 个账号的失败锁定生效时长为 0（锁定后立即自动解锁，等同于未锁定）：${fmtList(noLock.map(({ r }) => r.name))}。`, {
          advice: '为失败锁定设置有效的锁定时长；或改为锁定后需管理员解锁。',
          evidence,
        });
      }
      // 「取不到」不能当成「已设置」——那会把没配的库报成合规（方向相反的误判）
      if (unknown.length) {
        return R('unknown', `有 ${unknown.length} 个账号既未逐账号设置锁定时长、也取不到 DEFAULT profile 的 PASSWORD_LOCK_TIME，无法判定：${fmtList(unknown.map(({ r }) => r.name))}。请补 SYSDBA 权限或人工核对 \`DBA_PROFILES\`。`, { evidence });
      }
      return R('ok', `${onlyBuiltin ? '（本库无业务账号，按内置账号核对）' : ''}失败锁定的生效时长均非零。`, { evidence });
    },
  },
  {
    id: 'pwd.reuse_limit',
    domain: 'pwd',
    title: '口令重用限制',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.1(a)'],
    judge(c) {
      // 真机纠正：达梦**有**口令重用控制 —— 逐账号 `SYSUSERS.REUSE_MAX` / `REUSE_TIME`，
      // 以及 `DBA_PROFILES.DEFAULT.PASSWORD_REUSE_MAX` / `PASSWORD_REUSE_TIME`。
      // 原实现判「未取到」是错的。
      const profReuse = c.prof('PASSWORD_REUSE_MAX');
      const hasCol = c.pwd.reuseColumnPresent;
      if (!hasCol && !profReuse) {
        return R('unknown', '未在 `SYSUSERS` 与 `DBA_PROFILES` 取到口令重用配置，无法判断；请人工核对 `SELECT RESOURCE_NAME, LIMIT FROM DBA_PROFILES` 中的 PASSWORD_REUSE_MAX。');
      }
      const evidence = [
        ...(hasCol
          ? c.pwd.rows.map((r) => ({ 账号: r.name, REUSE_MAX: r.reuseMax === null ? '—' : String(r.reuseMax), REUSE_TIME: r.reuseTime === null ? '—' : String(r.reuseTime) }))
          : []),
        ...(profReuse ? [{ 账号: 'DEFAULT profile', REUSE_MAX: String(profReuse.raw ?? profReuse.value), REUSE_TIME: String(c.prof('PASSWORD_REUSE_TIME')?.raw ?? c.prof('PASSWORD_REUSE_TIME')?.value ?? '—') }] : []),
      ];
      const bizUnlimited = c.pwd.reuseColumnPresent ? c.bizPwd().filter((r) => r.reuseMax === 0) : [];
      const profUnlimited = profReuse?.unlimited === true;
      if (bizUnlimited.length) {
        return R('warn', `有 ${bizUnlimited.length} 个业务账号未限制口令重用（REUSE_MAX=0）：${fmtList(bizUnlimited.map((r) => r.name))}。`, { evidence });
      }
      if (profUnlimited) {
        const lv = c.biz().length ? 'warn' : 'info';
        return R(lv, `DEFAULT profile 的 PASSWORD_REUSE_MAX=UNLIMITED${c.biz().length ? '' : '（本库无业务账号，仅陈述）'}：可以反复使用同一个口令，口令轮换的防护效果会被抵消。`, {
          advice: '建议设置 PASSWORD_REUSE_MAX（如 5）与 PASSWORD_REUSE_TIME，禁止近期口令重用。',
          evidence,
        });
      }
      return R('ok', '口令重用限制已配置（逐账号与 DEFAULT profile 均非无限）。', { evidence });
    },
  },
  {
    id: 'pwd.idle_timeout',
    domain: 'pwd',
    title: '会话空闲超时',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: ['8.1.4.1(b)'],
    judge(c) {
      if (!c.pwd.rows.length) return R('unknown', '未取到逐账号口令策略，无法判断会话空闲超时。');
      const profIdle = c.prof('CONNECT_IDLE_TIME');
      const targets = c.bizPwd().length ? c.bizPwd() : c.pwd.rows;
      const onlyBuiltin = c.bizPwd().length === 0;
      const rows = targets.map((r) => ({ r, idle: effectiveLimit(c, 'idleTime', r.idleTime, 'CONNECT_IDLE_TIME') }));
      const evidence = rows.map(({ r, idle }) => ({
        账号: r.name,
        '逐账号 CONN_IDLE_TIME(分钟)': r.idleTime === null ? '—' : String(r.idleTime),
        '生效值': idle.unlimited ? 'UNLIMITED' : idle.value === null ? '未取到' : String(idle.value),
        来源: idle.source,
      }));
      const none = rows.filter(({ idle }) => idle.value === 0);
      const unlimited = rows.filter(({ idle }) => idle.unlimited);
      const unknown = rows.filter(({ idle }) => idle.value === null && !idle.unlimited);
      if (none.length) {
        return R(onlyBuiltin ? 'info' : 'warn', `${onlyBuiltin ? '（本库无业务账号，以下为内置账号）' : ''}有 ${none.length} 个账号未设置会话空闲超时（CONN_IDLE_TIME=0）：连接可无限期保持，终端离岗后会话仍有效。`, {
          items: none.map(({ r }) => `账号 ${r.name}（CONN_IDLE_TIME=0）`),
          advice: '为业务账号设置 CONNECT_IDLE_TIME（如 30 分钟）。',
          evidence,
        });
      }
      if (unlimited.length) {
        return R(onlyBuiltin ? 'info' : 'warn', `${onlyBuiltin ? '（本库无业务账号，以下为内置账号）' : ''}DEFAULT profile 的 CONNECT_IDLE_TIME=UNLIMITED，且以下 ${unlimited.length} 个账号未单独设置空闲超时。`, {
          items: unlimited.map(({ r }) => `账号 ${r.name}（未单独设置 → 落到 profile 的 UNLIMITED）`),
          evidence,
        });
      }
      if (unknown.length) {
        return R('unknown', `有 ${unknown.length} 个账号既未逐账号设置空闲超时、也取不到 DEFAULT profile 的 CONNECT_IDLE_TIME，无法判定：${fmtList(unknown.map(({ r }) => r.name))}。`, { evidence });
      }
      return R('ok', `${onlyBuiltin ? '（本库无业务账号，按内置账号核对）' : ''}会话空闲超时已设置。`, { evidence });
    },
  },

  // ==================================================== D 自主访问控制
  {
    id: 'dac.dba_holders',
    domain: 'dac',
    title: 'DBA 角色持有者',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['rolePrivs'],
    compliance: ['8.1.4.2(a)'],
    judge(c) {
      const rows = c.rows('rolePrivs').filter((r) => up(col(r, 'GRANTED_ROLE', 'ROLE')) === 'DBA');
      const suspicious = rows.filter((r) => notBuiltin(col(r, 'GRANTEE')));
      const evidence = rows.map((r) => ({ 账号: col(r, 'GRANTEE'), 角色: 'DBA', 可转授: col(r, 'ADMIN_OPTION') ?? '—' }));
      if (suspicious.length) {
        return R('crit', `有 ${suspicious.length} 个非默认管理账号持有 DBA 角色：${fmtList(suspicious.map((r) => col(r, 'GRANTEE')))}。DBA 角色在达梦中权限极大（含对象管理与数据操作）。`, {
          advice: '遵循最小权限：业务账号不应持有 DBA；确需管理权限时用细粒度系统权限替代。',
          evidence,
        });
      }
      return R('ok', `DBA 角色仅授予 ${rows.length} 个默认管理/采集账号，未发现越权授予。`, { evidence });
    },
  },
  {
    id: 'dac.dba_admin_option',
    domain: 'dac',
    title: 'DBA 角色可转授',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['rolePrivs'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      // 真机校准：SQL 里 ADMIN_OPTION 的值是 'Y'/'N'（不是 YES/NO）；
      // 且 **SYSDBA 自己持有带 ADMIN_OPTION 的 DBA 是安装默认**，不计为缺陷
      // （原来把它报成「权限会失控扩散」，属误报）。
      const all = c.rows('rolePrivs').filter((r) => up(col(r, 'GRANTED_ROLE', 'ROLE')) === 'DBA' && truthy(col(r, 'ADMIN_OPTION')));
      const suspicious = all.filter((r) => notBuiltin(col(r, 'GRANTEE')));
      const evidence = all.map((r) => ({ 账号: col(r, 'GRANTEE'), 角色: 'DBA', ADMIN_OPTION: String(col(r, 'ADMIN_OPTION')), 类别: isBuiltin(col(r, 'GRANTEE')) ? '内置/采集' : '业务' }));
      if (suspicious.length) {
        return R('warn', `DBA 角色带 ADMIN OPTION 授予了 ${suspicious.length} 个非默认账号：${fmtList(suspicious.map((r) => col(r, 'GRANTEE')))}，被授权者可继续把 DBA 转授他人，权限会失控扩散。`, {
          advice: '回收并重新以不带 ADMIN OPTION 的方式授予。',
          evidence,
        });
      }
      return R('ok', `带 ADMIN OPTION 的 DBA 授予仅存在于 ${all.length} 个内置/采集账号（安装默认）。`, { evidence });
    },
  },
  {
    id: 'dac.any_table_privs',
    domain: 'dac',
    title: 'ANY TABLE 类系统权限',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['sysPrivs'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const re = /ANY TABLE|ANY DICTIONARY|ANY VIEW|ANY INDEX|ANY PROCEDURE/i;
      const all = c.rows('sysPrivs').filter((r) => re.test(up(col(r, 'PRIVILEGE'))));
      // ★ 真机校准（2026-10-12）：达梦把这些权限挂在 **DBA 等内置角色**上，`GRANTEE` 是角色名。
      //   不区分「授予角色」与「授予账号」，真机上会误报 28 条。授予角色属设计如此。
      const toRoles = all.filter((r) => c.isRole(col(r, 'GRANTEE')));
      const rows = all.filter((r) => !c.isRole(col(r, 'GRANTEE')) && notBuiltin(col(r, 'GRANTEE')));
      const roleNote = toRoles.length ? `另有 ${toRoles.length} 条授予内置角色（${fmtList(toRoles.map((r) => col(r, 'GRANTEE')))}），属角色设计如此，不计为缺陷。` : '';
      if (rows.length) {
        return R('warn', `发现 ${rows.length} 条**直接授予账号**的 ANY 类权限：${fmtList(rows.map((r) => `${col(r, 'GRANTEE')}.${col(r, 'PRIVILEGE')}`))}。ANY 权限可跨越模式边界访问数据，范围过大。${roleNote}`, {
          advice: '改为按对象/按模式授予具体权限，或通过角色间接授予。',
          evidence: rows.map((r) => ({ 账号: col(r, 'GRANTEE'), 权限: col(r, 'PRIVILEGE'), 可转授: col(r, 'ADMIN_OPTION') ?? '—' })),
        });
      }
      return R('ok', `未发现直接授予账号的 ANY TABLE 类系统权限。${roleNote}`, { evidence: toRoles.slice(0, 15).map((r) => ({ 角色: col(r, 'GRANTEE'), 权限: col(r, 'PRIVILEGE') })) });
    },
  },
  {
    id: 'dac.grant_any',
    domain: 'dac',
    title: '授权管理权限',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['sysPrivs'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const all = c.rows('sysPrivs').filter((r) => /^GRANT ANY/i.test(up(col(r, 'PRIVILEGE'))));
      // ★ 真机校准：真机上 10 条 GRANT ANY 全部授予 **DBA / DB_AUDIT_ADMIN / DB_POLICY_ADMIN 角色**
      //   （角色本就该有这些权限）。只有「直接授予账号」才是越权信号。
      const toRoles = all.filter((r) => c.isRole(col(r, 'GRANTEE')));
      const rows = all.filter((r) => !c.isRole(col(r, 'GRANTEE')) && notBuiltin(col(r, 'GRANTEE')));
      const roleNote = toRoles.length ? `另有 ${toRoles.length} 条授予内置角色（${fmtList(toRoles.map((r) => col(r, 'GRANTEE')))}），属角色设计如此。` : '';
      if (rows.length) {
        return R('crit', `有 ${rows.length} 条 GRANT ANY 类权限**直接授予账号**：${fmtList(rows.map((r) => `${col(r, 'GRANTEE')}.${col(r, 'PRIVILEGE')}`))}。持有者可自行把任意权限（含 DBA）授出，等于绕过了授权管理。${roleNote}`, {
          advice: '回收该权限，授权操作收敛到 SYSDBA 或通过角色授予。',
          evidence: rows.map((r) => ({ 账号: col(r, 'GRANTEE'), 权限: col(r, 'PRIVILEGE'), 可转授: col(r, 'ADMIN_OPTION') ?? '—' })),
        });
      }
      return R('ok', `未发现直接授予账号的 GRANT ANY 类权限。${roleNote}`, { evidence: toRoles.slice(0, 15).map((r) => ({ 角色: col(r, 'GRANTEE'), 权限: col(r, 'PRIVILEGE') })) });
    },
  },
  {
    id: 'dac.user_admin_privs',
    domain: 'dac',
    title: '账号管理权限（CREATE/ALTER/DROP USER）',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['sysPrivs'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const re = /^(CREATE|ALTER|DROP) USER$/i;
      const all = c.rows('sysPrivs').filter((r) => re.test(up(col(r, 'PRIVILEGE'))));
      // ★ 真机校准：ALTER USER 授予 **DBA / DB_AUDIT_ADMIN / DB_POLICY_ADMIN 角色**是设计如此
      //   （这些角色本来就要管账号）。只有直接授予账号才等同于「可劫持任何身份」。
      const toRoles = all.filter((r) => c.isRole(col(r, 'GRANTEE')));
      const rows = all.filter((r) => !c.isRole(col(r, 'GRANTEE')) && notBuiltin(col(r, 'GRANTEE')));
      const roleNote = toRoles.length ? `另有 ${toRoles.length} 条授予内置角色（${fmtList(toRoles.map((r) => col(r, 'GRANTEE')))}），属角色设计如此。` : '';
      const alter = rows.filter((r) => up(col(r, 'PRIVILEGE')) === 'ALTER USER');
      const evidence = rows.map((r) => ({ 账号: col(r, 'GRANTEE'), 权限: col(r, 'PRIVILEGE') }));
      if (alter.length) {
        return R('crit', `有 ${alter.length} 条 ALTER USER 权限**直接授予账号**：${fmtList(alter.map((r) => col(r, 'GRANTEE')))}。**持有者可修改任意账号的口令与资源限制**，等同于可劫持任何身份。${roleNote}`, {
          advice: '立即回收直接授予账号的 ALTER USER；账号维护统一由 SYSDBA 或管理角色执行。',
          evidence,
        });
      }
      if (rows.length) return R('warn', `有 ${rows.length} 条账号创建/删除权限直接授予账号：${fmtList(rows.map((r) => `${col(r, 'GRANTEE')}.${col(r, 'PRIVILEGE')}`))}。${roleNote}`, { evidence });
      return R('ok', `未发现直接授予账号的账号管理权限。${roleNote}`);
    },
  },
  {
    id: 'dac.public_sys_privs',
    domain: 'dac',
    title: 'PUBLIC 的系统权限',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['sysPrivs'],
    compliance: ['8.1.4.2(a)'],
    judge(c) {
      const rows = c.rows('sysPrivs').filter((r) => up(col(r, 'GRANTEE')) === 'PUBLIC');
      const risky = rows.filter((r) => PUBLIC_RISKY_PRIV.test(up(col(r, 'PRIVILEGE'))));
      const evidence = risky.map((r) => ({ 权限: col(r, 'PRIVILEGE') }));
      if (risky.length) {
        return R('warn', `PUBLIC 被授予 ${risky.length} 项**数据库级高危**系统权限：${fmtList(risky.map((r) => col(r, 'PRIVILEGE')))}。PUBLIC 对全体账号生效，任何新账号都会继承。`, {
          advice: '回收 PUBLIC 上的账号管理 / 库级管理 / ANY 类权限。',
          evidence,
        });
      }
      return R(
        'ok',
        `PUBLIC 共 ${rows.length} 项系统权限，**均为达梦默认的对象类权限**（ALTER/DROP TABLE、EXECUTE PACKAGE、GRANT SCHEMA 等，只在自己有权的对象上生效），未发现账号管理、库级管理或 ANY 类高危权限。`,
        { evidence: rows.slice(0, 20).map((r) => ({ 权限: col(r, 'PRIVILEGE') })) },
      );
    },
  },
  {
    id: 'dac.public_obj_privs',
    domain: 'dac',
    title: 'PUBLIC 的对象权限',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['tabPrivs'],
    compliance: ['8.1.4.2(a)'],
    judge(c) {
      const rows = c.rows('tabPrivs').filter((r) => up(col(r, 'GRANTEE')) === 'PUBLIC');
      // 真机校准：真机上 236 条 PUBLIC 对象权限**全部**是系统属主（SYS/SYSJOB/SYSDBA）下的
      // 字典视图与系统过程（如 ALL_TABLES、SP_*_BAKSET_REMOVE_BATCH），属达梦默认。
      // 原来不分属主一律告警，等于给每个库都报一条假问题。
      const sys = rows.filter((r) => SYSTEM_OWNERS.includes(up(col(r, 'OWNER'))));
      const biz = rows.filter((r) => !SYSTEM_OWNERS.includes(up(col(r, 'OWNER'))));
      if (biz.length) {
        return R('warn', `有 ${biz.length} 条**业务对象**的权限授予了 PUBLIC：${fmtList(biz.map((r) => `${col(r, 'OWNER')}.${col(r, 'TABLE_NAME')}(${col(r, 'PRIVILEGE')})`))}。全体账号可直接访问这些对象。`, {
          advice: '仅对确实需要全局可见的字典类对象保留 PUBLIC 授权。',
          evidence: biz.slice(0, 30).map((r) => ({ 对象: `${col(r, 'OWNER')}.${col(r, 'TABLE_NAME')}`, 权限: col(r, 'PRIVILEGE') })),
        });
      }
      return R('ok', `PUBLIC 的 ${rows.length} 条对象权限**全部落在系统属主**（${fmtList(sys.map((r) => col(r, 'OWNER')))}）的字典/系统对象上，属达梦默认；未发现业务对象被授予 PUBLIC。`, {
        evidence: sys.slice(0, 15).map((r) => ({ 对象: `${col(r, 'OWNER')}.${col(r, 'TABLE_NAME')}`, 权限: col(r, 'PRIVILEGE') })),
      });
    },
  },
  {
    id: 'dac.custom_roles',
    domain: 'dac',
    title: '角色清单（内置与自定义）',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['roles'],
    compliance: ['8.1.4.2(a)'],
    judge(c) {
      const rows = c.rows('roles');
      if (!rows.length) return R('unknown', '未取到角色清单（`DBA_ROLES` 无结果），需 SYSDBA 权限。');
      // 真机纠正：DBA_ROLES 的列是 ROLE（原来只找 NAME/ROLE_NAME，真机上取到空清单）
      const names = rows.map((r) => String(col(r, 'ROLE', 'NAME', 'ROLE_NAME') ?? '').trim()).filter(Boolean);
      if (!names.length) {
        return R('unknown', `已读到 ${rows.length} 行角色，但未识别出角色名列（首行列名：${(c.res.roles?.columns ?? []).join('、') || '未知'}），需人工核对。`);
      }
      const custom = names.filter((n) => !KNOWN_ROLES.includes(up(n)));
      return R(
        'info',
        `共 ${names.length} 个角色，其中不在内置名单内的有 ${custom.length} 个${custom.length ? `：${fmtList(custom)}` : ''}。自定义角色应逐个核对权限范围与持有人。`,
        { evidence: custom.slice(0, 30).map((n) => ({ 角色: n })) },
      );
    },
  },
  {
    id: 'dac.grant_schema',
    domain: 'dac',
    title: '模式级授权开关',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const p = c.p('GRANT_SCHEMA');
      if (!p) return R('na', '本版本参数表中不存在 `GRANT_SCHEMA`，该版本不提供按模式授权。');
      if (truthy(p.value)) {
        return R('warn', `模式级授权已开启（GRANT_SCHEMA=${p.value}）：一条 GRANT 即可把整个模式的权限授出，容易造成批量过度授权。`, {
          advice: '除非确有必要，保持 GRANT_SCHEMA=0，按具体对象授权。',
          evidence: [{ 参数: 'GRANT_SCHEMA', 当前值: String(p.value), 默认值: String(p.def ?? '—') }],
        });
      }
      return R('ok', `模式级授权未开启（GRANT_SCHEMA=${p.value}）。`);
    },
  },

  // ==================================================== E 职责分离
  {
    id: 'sod.priv_flag',
    domain: 'sod',
    title: '三权 / 四权分立',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const p = c.p('PRIV_FLAG');
      if (!p) {
        return R(
          'na',
          `本版本参数表中不存在 \`PRIV_FLAG\`：${c.shape.edition ?? '普通版'}不提供三权/四权分立配置，该项不适用。` +
            '（职责分离需以管理措施补偿：管理员、审计、备份等职责由不同人员承担。）',
        );
      }
      const mode = String(p.value) === '1' ? '四权分立（SYSDBA/SYSSSO/SYSAUDITOR/SYSDBO）' : '三权分立（SYSDBA/SYSSSO/SYSAUDITOR）';
      return R('ok', `已启用${mode}，PRIV_FLAG=${p.value}。职责分离已由数据库机制保障。`, {
        advice: String(p.value) === '1' ? null : '如需更细粒度的职责分离，安全版可考虑启用四权分立（PRIV_FLAG=1，需重新建库）。',
        evidence: [{ 参数: 'PRIV_FLAG', 当前值: String(p.value), 默认值: String(p.def ?? '—') }],
      });
    },
  },
  {
    id: 'sod.admin_availability',
    domain: 'sod',
    title: '各管理员账号可用性',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['users'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const admins = c.admins();
      const evidence = admins.map((a) => ({ 角色: a.name, 是否存在: a.user ? '存在' : '不存在', 状态: a.user?.status || '—' }));
      const unavailable = admins.filter((a) => !a.user || (a.user.status && a.user.status !== 'OPEN')).map((a) => a.name);
      if (unavailable.length === 0) return R('ok', `职责分离所需的 ${admins.length} 个管理员账号均存在且可用。`, { evidence });
      if (!c.shape.secure) {
        return R(
          'info',
          `以下管理员账号当前不可用：${unavailable.join('、')}。${c.shape.edition ?? '普通版'}不提供三权/四权分立，` +
            '审计员/安全员账号默认不启用属安装默认值；但请确认审计与安全策略由谁实际负责。',
          { evidence },
        );
      }
      const auditorDown = unavailable.includes('SYSAUDITOR');
      const ssoDown = unavailable.includes('SYSSSO');
      const detail = [auditorDown ? '审计员 SYSAUDITOR 不可用（无人配置/查看审计）' : null, ssoDown ? '安全员 SYSSSO 不可用（无人管理安全策略）' : null].filter(Boolean).join('；');
      return R('warn', `安全版实例中以下管理员账号不可用：${unavailable.join('、')}。${detail ? `其中：${detail}。` : ''}职责分离要求各角色都能实际履职，账号不可用会让分立名存实亡。`, { evidence });
    },
  },
  {
    id: 'sod.admin_overlap',
    domain: 'sod',
    title: '管理员权限交叉',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['rolePrivs'],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const byUser = new Map();
      for (const r of c.rows('rolePrivs')) {
        const g = up(col(r, 'GRANTEE'));
        const role = up(col(r, 'GRANTED_ROLE', 'ROLE'));
        if (!g) continue;
        if (!byUser.has(g)) byUser.set(g, new Set());
        byUser.get(g).add(role);
      }
      const AUDIT_RE = /AUDIT|POLICY|SECURITY/i;
      const overlapped = [];
      for (const [g, roles] of byUser) {
        const hasDba = roles.has('DBA');
        const auditRoles = [...roles].filter((r) => AUDIT_RE.test(r));
        if (hasDba && auditRoles.length) overlapped.push({ 账号: g, 角色: [...roles].join('、'), 冲突角色: auditRoles.join('、') });
      }
      if (overlapped.length) {
        const biz = overlapped.filter((o) => notBuiltin(o.账号));
        const msg =
          `有 ${overlapped.length} 个账号同时持有 DBA 与审计/安全类角色：` +
          overlapped.map((o) => `${o.账号}(${o.冲突角色})`).join('、') +
          '。数据库管理员兼任审计员，等于自己监督自己，违反职责分离。';
        return biz.length
          ? R('crit', msg, { advice: 'DBA 与审计/安全角色必须由不同账号、不同人员持有。', evidence: overlapped })
          : R('warn', msg + '（均为内置管理员账号，若贵司确实由同一人分管，需以管理措施补偿）。', { advice: '建议由不同人员分别保管 DBA 与审计账号。', evidence: overlapped });
      }
      return R('ok', '未发现同时持有 DBA 与审计/安全类角色的账号。');
    },
  },

  // ==================================================== F 强制访问控制
  {
    id: 'mac.edition',
    domain: 'mac',
    title: '是否具备强制访问控制能力',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['buildType'],
    compliance: ['8.1.4.2(g)'],
    judge(c) {
      const s = c.shape;
      if (s.secure) {
        return R('info', `版本类型为**安全版**（${s.secureSignals.join('；')}），强制访问控制（安全标记）在本实例可用。`);
      }
      if (!s.edition) {
        return R('unknown', `未取到 \`V$INSTANCE.ID_CODE\` 解出的版本类型（判据来源：${s.editionSource}），无法判定是否具备 MAC 能力；请人工核对数据库授权版本。`);
      }
      return R(
        'na',
        `版本类型为**${s.edition}**（${s.idCode || s.secureSignals.join('；')}）：普通版不提供强制访问控制，该项**不适用**，不构成不合规。` +
          (s.macObjectCount
            ? `⚠️ 注意：本实例字典里存在 ${s.macObjectCount} 个 MAC 相关对象，但**这不能作为安全版的判据** —— 普通版字典里同样存在。`
            : '') +
          '若贵司要求该能力，需采购安全版并重新建库。',
      );
    },
  },
  {
    id: 'mac.policy_objects',
    domain: 'mac',
    title: 'MAC 策略与安全标记对象',
    level: 'warn',
    priv: 'SYSDBA',
    edition: 'secure',
    needs: ['macObjs'],
    compliance: ['8.1.4.2(g)'],
    judge(c) {
      const rows = c.rows('macObjs');
      const labels = rows.filter((r) => /MACLABEL|SECLABEL|PRIV_LABEL/i.test(String(col(r, 'OBJECT_NAME'))));
      const policies = rows.filter((r) => /MACPOLICY|POLICY_LABEL/i.test(String(col(r, 'OBJECT_NAME'))));
      const evidence = rows.slice(0, 30).map((r) => ({ 属主: col(r, 'OWNER'), 对象: col(r, 'OBJECT_NAME'), 类型: col(r, 'OBJECT_TYPE') }));
      if (!rows.length) {
        return R('warn', '安全版实例上未发现任何强制访问控制策略或安全标记对象：MAC 能力未被使用，敏感数据未受安全标记约束。', {
          advice: '如需满足等保「重要主体/客体设置安全标记」要求，需以 SYSSSO 建立安全策略、级别/范围/组，并为主体与客体打标。',
        });
      }
      if (!policies.length) {
        return R('warn', `发现 ${rows.length} 个安全标记类对象但未见策略对象，安全标记可能未成体系。`, { evidence });
      }
      return R('info', `发现策略对象 ${policies.length} 个、标记类对象 ${labels.length} 个。**标记的实际覆盖率需进一步核对**（P1，见 DESIGN §10）。`, { evidence });
    },
  },

  // ==================================================== G 安全审计
  {
    id: 'audit.enable',
    domain: 'audit',
    title: '审计开关',
    level: 'crit',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.3(a)'],
    judge(c) {
      const p = c.p('ENABLE_AUDIT');
      if (!p) return R('na', '本版本参数表中不存在 `ENABLE_AUDIT`，无法评估审计开关。');
      const v = String(p.value ?? '').trim();
      const dicts = c.rows('auditDict').slice(0, 10).map((r) => `${col(r, 'OWNER')}.${col(r, 'OBJECT_NAME')}`);
      const evidence = [
        { 参数: 'ENABLE_AUDIT', 当前值: v || '(空)', 默认值: String(p.def ?? '—'), 含义: '0=关闭，1=普通审计，2=普通审计+实时审计' },
        ...(dicts.length ? [{ 本版本审计字典: dicts.join('、') }] : []),
      ];
      if (v === '0' || v === '') {
        return R('crit', `数据库审计未开启（ENABLE_AUDIT=${v || '空'}）：任何操作都不留痕，无法追溯谁在什么时间做了什么，直接违反等保安全审计要求。`, {
          advice: '以 SYSAUDITOR 登录执行 `SP_SET_ENABLE_AUDIT(1)`（实时审计为 2），并用 `SP_AUDIT_STMT` / `SP_AUDIT_OBJECT` 配置审计项。',
          evidence,
        });
      }
      if (v !== '1' && v !== '2') return R('unknown', `ENABLE_AUDIT 取值 \`${v}\` 不是已知的 0/1/2，需人工核对。`, { evidence });
      return R('ok', `审计已开启（ENABLE_AUDIT=${v}）。`, { evidence });
    },
  },
  {
    id: 'audit.realtime',
    domain: 'audit',
    title: '实时审计',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.3(a)'],
    judge(c) {
      const p = c.p('ENABLE_AUDIT');
      if (!p) return R('na', '本版本参数表中不存在 `ENABLE_AUDIT`。');
      const v = String(p.value ?? '').trim();
      if (v === '2') return R('ok', '已开启实时审计（ENABLE_AUDIT=2）。');
      if (v === '1') {
        return R('warn', '审计为普通模式（ENABLE_AUDIT=1），未开启实时审计：高风险操作无法即时告警，只能在事后查阅记录。', {
          advice: '对关键操作（用户/权限变更、敏感表访问）建议开启实时审计（ENABLE_AUDIT=2）。',
          evidence: [{ 参数: 'ENABLE_AUDIT', 当前值: v, 期望: '2' }],
        });
      }
      return R('na', `审计未开启（ENABLE_AUDIT=${v || '空'}），本项无从谈起；请先看「审计开关」。`);
    },
  },
  {
    id: 'audit.records_exist',
    domain: 'audit',
    title: '审计是否真在产生记录',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['auditRecords'],
    compliance: ['8.1.4.3(b)'],
    judge(c) {
      const auditOn = String(c.pv('ENABLE_AUDIT') ?? '').trim();
      if (auditOn === '0' || auditOn === '') return R('na', '审计开关本身未开启，审计记录为空的结论没有意义；请先处理「审计开关」。');
      const rows = c.rows('auditRecords');
      const n = rows.length ? num(col(rows[0], 'N', 'CNT', 'COUNT')) : null;
      if (n === null) return R('unknown', '未取到审计记录行数（查询结果无法解析），需人工核对 `V$AUDITRECORDS`。');
      if (n === 0) {
        return R('warn', '审计开关已开启，但审计记录为 **0 行**：审计可能未真正生效（缺少审计策略、审计文件不可写、或记录被清理）。', {
          advice: '以 SYSAUDITOR 登录，确认已用 `SP_AUDIT_STMT` / `SP_AUDIT_OBJECT` 配置审计项，并检查审计文件目录可写、空间充足。',
          evidence: [{ 审计记录行数: '0', ENABLE_AUDIT: auditOn }],
        });
      }
      return R('ok', `审计记录存在（共 ${n} 行），说明审计链路在产出数据。`, { evidence: [{ 审计记录行数: String(n), ENABLE_AUDIT: auditOn }] });
    },
  },
  {
    id: 'audit.file_size',
    domain: 'audit',
    title: '审计文件大小配置',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.3(c)'],
    judge(c) {
      const p = c.p('AUDIT_MAX_FILE_SIZE');
      if (!p) return R('na', '本版本参数表中不存在 `AUDIT_MAX_FILE_SIZE`。');
      const v = String(p.value ?? '').trim();
      const evidence = [{ 参数: 'AUDIT_MAX_FILE_SIZE', 当前值: v || '(空)', 默认值: String(p.def ?? '—') }];
      if (v === '' || v === '0') {
        return R('warn', `审计文件大小未配置（AUDIT_MAX_FILE_SIZE=${v || '空'}）：审计文件可能快速膨胀或空间不可控，存在审计中断风险。`, {
          advice: '结合审计量与磁盘容量设置单个审计文件上限，并为审计目录单独规划空间与保留周期。',
          evidence,
        });
      }
      return R('info', `审计文件大小上限为 ${v}（单位以本版本为准，见参数描述）。`, { evidence });
    },
  },
  {
    id: 'audit.file_full_mode',
    domain: 'audit',
    title: '审计文件写满策略',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.3(c)'],
    judge(c) {
      const p = c.p('AUDIT_FILE_FULL_MODE');
      if (!p) return R('na', '本版本参数表中不存在 `AUDIT_FILE_FULL_MODE`。');
      const v = String(p.value ?? '').trim();
      // ⚠️ DESIGN §8#4：取值语义（写满后报错还是覆盖）仍未确认，**只陈述取值、不判方向**。
      //    真机实测本环境 AUDIT_FILE_FULL_MODE=3、DEFAULT_VALUE=3，但 3 的含义需要查手册确认。
      return R('info', `审计文件写满策略 AUDIT_FILE_FULL_MODE=${v || '(空)'}（默认值 ${p.def ?? '—'}）。⚠️ 该取值的语义（写满后报错还是覆盖旧记录）**本插件未确认**，请对照《DM8 管理员手册》：若为覆盖策略，审计记录可能被滚动删除，需配合外部归档。`, {
        evidence: [{ 参数: 'AUDIT_FILE_FULL_MODE', 当前值: v || '(空)', 默认值: String(p.def ?? '—'), 描述: String(p.desc ?? '') }],
      });
    },
  },
  {
    id: 'audit.svr_log',
    domain: 'audit',
    title: 'SQL 日志（SVR_LOG）',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.3(a)'],
    judge(c) {
      const p = c.p('SVR_LOG');
      if (!p) return R('na', '本版本参数表中不存在 `SVR_LOG`。');
      const on = truthy(p.value);
      const evidence = [{ 参数: 'SVR_LOG', 当前值: String(p.value ?? '(空)'), 默认值: String(p.def ?? '—') }];
      if (on) return R('info', 'SVR_LOG 已开启：SQL 文本会落盘，安全上有利（可追溯），但有性能开销与敏感数据落盘风险；请确认日志目录权限与保留周期。', { evidence });
      return R('info', 'SVR_LOG 未开启。数据库审计（若有）不受影响，本项仅作记录。', { evidence });
    },
  },

  // ==================================================== H 通信安全
  {
    id: 'comm.enable_encrypt',
    domain: 'comm',
    title: '通信加密',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.1(c)', '8.1.4.8(a)'],
    judge(c) {
      const p = c.p('ENABLE_ENCRYPT');
      if (!p) return R('na', '本版本参数表中不存在 `ENABLE_ENCRYPT`，无法评估通信加密开关。');
      const v = String(p.value ?? '').trim();
      const evidence = [{ 参数: 'ENABLE_ENCRYPT', 当前值: v || '(空)', 默认值: String(p.def ?? '—') }];
      if (truthy(v)) return R('ok', `通信加密已开启（ENABLE_ENCRYPT=${v}）。`, { evidence });
      return R('warn', `通信加密未开启（ENABLE_ENCRYPT=${v || '空'}）：客户端与数据库之间的报文明文传输，口令与数据可被链路嗅探。`, {
        advice: '启用 SSL 通信加密并配置证书；等保要求对远程管理/传输过程采取加密措施（该条在二级与三级均要求）。',
        evidence,
      });
    },
  },
  {
    id: 'comm.encrypt_params',
    domain: 'comm',
    title: '加密相关参数清单',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['params'],
    compliance: ['8.1.4.8(a)'],
    judge(c) {
      const hits = [];
      for (const p of c.params.values()) {
        if (/SSL|ENCRYPT|CIPHER|RADIUS|UKEY/i.test(p.name)) hits.push({ 参数: p.name, 当前值: String(p.value ?? ''), 说明: String(p.desc ?? '').slice(0, 60) });
      }
      if (!hits.length) return R('info', '未在参数表中发现通信/加密相关参数（本版本可能未编译该类能力，或未配置）。');
      return R('info', `发现 ${hits.length} 个通信/加密相关参数，供核对配置完整性（见证据）。`, { evidence: hits.slice(0, 25) });
    },
  },

  // ==================================================== I 存储加密
  {
    id: 'enc.storage_encrypt',
    domain: 'enc',
    title: '存储加密能力与启用迹象',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['params', 'encObjs'],
    compliance: ['8.1.4.8(b)'],
    judge(c) {
      // 排除 ENABLE_ENCRYPT：那是**通信**加密开关（comm 域已单独判）
      const encParams = [...c.params.values()].filter((p) => /ENCRYPT/i.test(p.name) && !/^ENABLE_ENCRYPT$/i.test(p.name));
      // ⚠️ encObjs 里那几个是**字典视图**（ALL/DBA/USER_ENCRYPTED_COLUMNS），只证明「本版本支持列加密」，
      //    不等于任何数据被加密 —— 早期把它们当「相关对象 N 个」来报是误导（2026-10-12 真机纠正）。
      const dict = c.rows('encObjs');
      const cntRow = c.rows('encColumns')[0];
      const nCols = cntRow ? c.num(c.col(cntRow, 'N', 'CNT')) : null;
      const colList = c.rows('encColumnList')
        .slice(0, 20)
        .map((r) => `${c.col(r, 'OWNER')}.${c.col(r, 'TABLE_NAME')}.${c.col(r, 'COLUMN_NAME')}`);
      const evidence = [
        ...(nCols === null ? [] : [{ 类型: '加密列', 名称: `共 ${nCols} 列`, 值: 'DBA_ENCRYPTED_COLUMNS' }]),
        ...colList.map((x) => ({ 类型: '加密列', 名称: x, 值: '' })),
        ...encParams.slice(0, 15).map((p) => ({ 类型: '参数', 名称: p.name, 值: String(p.value ?? '') })),
        ...dict.slice(0, 15).map((r) => ({ 类型: '字典视图', 名称: `${c.col(r, 'OWNER')}.${c.col(r, 'OBJECT_NAME')}`, 值: String(c.col(r, 'OBJECT_TYPE') ?? '') })),
      ];
      if (nCols === null) {
        return R('info', '未取到表列加密元数据（`DBA_ENCRYPTED_COLUMNS` 不可读或本版本无此视图），无法判断列加密覆盖；证据里的字典视图可佐证该能力是否存在。', { evidence });
      }
      if (nCols > 0) {
        return R('ok', `已检测到 **${nCols} 个加密列**（取自 \`DBA_ENCRYPTED_COLUMNS\`）：重要数据的存储保密性已有措施落地。`, {
          items: colList.slice(0, 12),
          evidence,
        });
      }
      return R(
        'info',
        '`DBA_ENCRYPTED_COLUMNS` 为 **0 行**：未发现任何表列加密；全库/表空间加密在建库时（dminit）确定，库建好后不出现在运行参数里。' +
          '若「重要数据存储保密性」是要求项，需建库时启用透明加密或对敏感列做列加密。',
        { evidence },
      );
    },
  },

  // ==================================================== J 资源限制
  {
    id: 'res.profile_inventory',
    domain: 'res',
    title: 'PROFILE 资源限制清单',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['profiles'],
    compliance: [],
    hardening: '资源限制属**加固项**：等保 2.0「安全计算环境」无对应明确条款（该要求在等保 1.0 的「主机安全-资源控制」中），列出仅供加固参考',
    judge(c) {
      const rows = c.rows('profiles');
      if (!rows.length) return R('info', '本版本 `DBA_PROFILES` 无数据或该字典不可用，无法核对 PROFILE 资源限制。');
      const evidence = rows.map((r) => ({
        PROFILE: String(col(r, 'PROFILE', 'NAME') ?? ''),
        资源项: String(col(r, 'RESOURCE_NAME', 'RESOURCE') ?? ''),
        类型: String(col(r, 'RESOURCE_TYPE') ?? ''),
        限制: String(col(r, 'LIMIT', 'LIMIT_VALUE') ?? ''),
      }));
      // 真机实测：DEFAULT profile 里 CPU_PER_SESSION / CPU_PER_CALL / MEM_SPACE /
      // READ_PER_SESSION / SESSION_PER_USER / CONNECT_TIME / CONNECT_IDLE_TIME 全是 UNLIMITED。
      // ★ 校准：本项只盯**内核类（KERNEL）**资源 —— 口令类（PASSWORD_*）的 UNLIMITED 由
      //   pwd 域的单项判定，混进来会让同一件事被报两次。
      const unlimited = [...c.profiles.entries()].flatMap(([p, m]) =>
        [...m.entries()].filter(([, v]) => v.unlimited && v.type === 'KERNEL').map(([k]) => `${p}.${k}`),
      );
      const pwdUnlimited = [...c.profiles.entries()].flatMap(([p, m]) =>
        [...m.entries()].filter(([, v]) => v.unlimited && v.type === 'PASSWORD').map(([k]) => `${p}.${k}`),
      );
      const pwdNote = pwdUnlimited.length ? `另有 ${pwdUnlimited.length} 项口令类限制为 UNLIMITED（${fmtList(pwdUnlimited, 6)}），由「口令策略」域的单项判定。` : '';
      if (unlimited.length) {
        return R(
          'warn',
          `PROFILE 中有 ${unlimited.length} 项**内核资源**限制为 UNLIMITED：任一会话/用户可无上限占用 CPU、内存与连接数，构成拒绝服务面。${pwdNote}`,
          {
            items: unlimited.map(profileLabel),
            advice: '按业务容量为 DEFAULT profile 设置具体上限（CPU_PER_SESSION、MEM_SPACE、SESSION_PER_USER、CONNECT_TIME、CONNECT_IDLE_TIME）。',
            evidence,
          },
        );
      }
      return R('ok', `共 ${rows.length} 条 PROFILE 资源限制，内核资源未发现 UNLIMITED。${pwdNote}`, {
        items: pwdUnlimited.map(profileLabel),
        evidence,
      });
    },
  },
  {
    id: 'res.session_limit',
    domain: 'res',
    title: '单用户会话数上限',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: [],
    hardening: '资源限制属**加固项**：等保 2.0「安全计算环境」无对应明确条款（该要求在等保 1.0 的「主机安全-资源控制」中），列出仅供加固参考',
    judge(c) {
      if (!c.pwd.rows.length) return R('unknown', '未取到逐账号资源限制，无法判断会话数上限。');
      if (!c.pwd.sessionColumnPresent) {
        return R('unknown', '本版本的 `SYSUSERS` 未暴露 `SESS_PER_USER` 列（降级查询生效），会话数上限需人工核对。');
      }
      const profSession = c.prof('SESSION_PER_USER');
      const targets = c.bizPwd().length ? c.bizPwd() : c.pwd.rows;
      const onlyBuiltin = c.bizPwd().length === 0;
      const rows = targets.map((r) => ({ r, eff: effectiveLimit(c, 'sessionsPerUser', r.sessionsPerUser, 'SESSION_PER_USER') }));
      const evidence = rows.map(({ r, eff }) => ({
        账号: r.name,
        '逐账号 SESS_PER_USER': r.sessionsPerUser === null ? '—' : String(r.sessionsPerUser),
        '生效值': eff.unlimited ? 'UNLIMITED' : eff.value === null ? '未取到' : String(eff.value),
        来源: eff.source,
      }));
      const none = rows.filter(({ eff }) => eff.value === 0 || eff.unlimited);
      const unknown = rows.filter(({ eff }) => eff.value === null && !eff.unlimited);
      if (none.length) {
        return R(onlyBuiltin ? 'info' : 'warn', `${onlyBuiltin ? '（本库无业务账号，以下为内置账号）' : ''}有 ${none.length} 个账号未限制并发会话数（逐账号 SESS_PER_USER=0${profSession?.unlimited ? '，且 DEFAULT profile=UNLIMITED' : ''}）：单个账号可占满连接数，形成拒绝服务面。`, {
          items: none.map(({ r, eff }) => `账号 ${r.name}（${eff.unlimited ? '未单独设置 → profile=UNLIMITED' : 'SESS_PER_USER=0'}）`),
          advice: '为业务账号设置合理的会话数上限（与应用连接池上限一致），或收紧 DEFAULT profile。',
          evidence,
        });
      }
      if (unknown.length) {
        return R('unknown', `有 ${unknown.length} 个账号既未逐账号设置并发会话数上限、也取不到 DEFAULT profile 的 SESSION_PER_USER，无法判定：${fmtList(unknown.map(({ r }) => r.name))}。`, { evidence });
      }
      return R('ok', `${onlyBuiltin ? '（本库无业务账号，按内置账号核对）' : ''}并发会话数上限已设置。`, { evidence });
    },
  },
  {
    id: 'res.cpu_limit',
    domain: 'res',
    title: '单会话 CPU 限制',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['profiles'],
    compliance: [],
    hardening: '资源限制属**加固项**：等保 2.0「安全计算环境」无对应明确条款（该要求在等保 1.0 的「主机安全-资源控制」中），列出仅供加固参考',
    judge(c) {
      // 真机纠正：CPU 限制不在 SYSUSERS，在 DBA_PROFILES（CPU_PER_SESSION / CPU_PER_CALL）。
      // 原来判「未取到」，真机上其实可判定。
      const perSession = c.prof('CPU_PER_SESSION');
      const perCall = c.prof('CPU_PER_CALL');
      if (!perSession && !perCall) return R('unknown', '未在 `DBA_PROFILES` 取到 `CPU_PER_SESSION`，需人工核对 PROFILE 配置。');
      const evidence = [
        { 资源项: 'CPU_PER_SESSION', 限制: String(perSession?.raw ?? '未取到') },
        { 资源项: 'CPU_PER_CALL', 限制: String(perCall?.raw ?? '未取到') },
      ];
      if (perSession?.unlimited) {
        return R('warn', 'DEFAULT profile 的 CPU_PER_SESSION=UNLIMITED：单个大查询可耗尽实例 CPU，影响其他会话。', {
          advice: '为 DEFAULT profile 或高风险账号设置 CPU_PER_SESSION / CPU_PER_CALL 上限。',
          evidence,
        });
      }
      return R('ok', `CPU 限制已设置（CPU_PER_SESSION=${perSession?.raw ?? '—'}，CPU_PER_CALL=${perCall?.raw ?? '—'}）。`, { evidence });
    },
  },
  {
    id: 'res.mem_limit',
    domain: 'res',
    title: '单用户内存限制',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['profiles'],
    compliance: [],
    hardening: '资源限制属**加固项**：等保 2.0「安全计算环境」无对应明确条款（该要求在等保 1.0 的「主机安全-资源控制」中），列出仅供加固参考',
    judge(c) {
      const mem = c.prof('MEM_SPACE');
      if (!mem) return R('unknown', '未在 `DBA_PROFILES` 取到 `MEM_SPACE`，需人工核对 PROFILE 配置。');
      const evidence = [{ 资源项: 'MEM_SPACE', 限制: String(mem.raw ?? '未取到') }];
      if (mem.unlimited) {
        return R('warn', 'DEFAULT profile 的 MEM_SPACE=UNLIMITED：大排序 / 大哈希可无限挤占实例内存。', {
          advice: '为 DEFAULT profile 或高风险账号设置 MEM_SPACE 上限。',
          evidence,
        });
      }
      return R('ok', `内存限制已设置（MEM_SPACE=${mem.raw}）。`, { evidence });
    },
  },
  {
    id: 'res.max_sessions',
    domain: 'res',
    title: '实例会话上限与当前用量',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['params', 'sessions'],
    compliance: [],
    hardening: '资源限制属**加固项**：等保 2.0「安全计算环境」无对应明确条款（该要求在等保 1.0 的「主机安全-资源控制」中），列出仅供加固参考',
    judge(c) {
      const p = c.p('MAX_SESSIONS');
      if (!p) return R('unknown', "参数表中未取到 `MAX_SESSIONS`，无法判断实例会话上限（可人工执行 `SELECT SF_GET_PARA_VALUE(2,'MAX_SESSIONS') FROM DUAL` 核对）。");
      const max = num(p.value);
      const cur = c.rows('sessions').reduce((a, r) => a + (num(col(r, 'CNT')) ?? 0), 0);
      if (max === null || max === 0) {
        return R('info', `MAX_SESSIONS=${String(p.value ?? '')}（未设上限或取值无法解析），当前会话数 ${cur}。`, {
          evidence: [{ 参数: 'MAX_SESSIONS', 当前值: String(p.value ?? ''), 当前会话数: String(cur) }],
        });
      }
      const pct = Math.round((cur / max) * 1000) / 10;
      const evidence = [{ 参数: 'MAX_SESSIONS', 当前值: String(max), 当前会话数: String(cur), 使用率: `${pct}%` }];
      if (pct > c.th.maxSessionsWarnPct) {
        return R('warn', `实例会话数已达上限的 ${pct}%（${cur}/${max}）：连接空间被占满会导致合法用户无法登录（拒绝服务）。`, {
          advice: '排查连接池泄漏与空闲连接；必要时调大 MAX_SESSIONS 并同步调整操作系统句柄限制。',
          evidence,
        });
      }
      return R('ok', `实例会话上限 ${max}，当前 ${cur} 个（${pct}%），余量充足。`, { evidence });
    },
  },
  {
    id: 'res.unlimited_admins',
    domain: 'res',
    title: '管理员账号的资源限制',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['pwdPolicy'],
    compliance: [],
    hardening: '资源限制属**加固项**：等保 2.0「安全计算环境」无对应明确条款（该要求在等保 1.0 的「主机安全-资源控制」中），列出仅供加固参考',
    judge(c) {
      if (!c.pwd.rows.length) return R('unknown', '未取到逐账号资源限制，无法判断管理员账号的资源限制。');
      if (!c.pwd.sessionColumnPresent) {
        return R('unknown', '本版本的 `SYSUSERS` 未暴露 `SESS_PER_USER` 列（降级查询生效），无法判断管理员账号的资源限制。');
      }
      const admins = c.pwd.rows.filter((r) => ['SYSDBA', 'SYSAUDITOR', 'SYSSSO'].includes(r.name.toUpperCase()));
      if (!admins.length) return R('unknown', '逐账号资源限制结果中未找到管理员账号记录。');
      const evidence = admins.map((r) => ({
        账号: r.name,
        '会话上限': r.sessionsPerUser === null ? '—' : String(r.sessionsPerUser),
        '空闲超时': r.idleTime === null ? '—' : String(r.idleTime),
      }));
      const unlimited = admins.filter((r) => r.sessionsPerUser === 0 && r.idleTime === 0);
      if (unlimited.length) {
        return R('info', `管理员账号中有 ${unlimited.length} 个既无并发会话上限、也无空闲超时。属安装默认值，可接受；如需加固可按贵司规范设置。`, {
          items: unlimited.map((r) => `账号 ${r.name}（SESS_PER_USER=0、CONN_IDLE_TIME=0）`),
          evidence,
        });
      }
      return R('ok', '管理员账号已配置资源限制。', { evidence });
    },
  },

  // ==================================================== K 访问路径
  {
    id: 'net.session_sources',
    domain: 'net',
    title: '当前连接的来源分布',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['sessions'],
    compliance: ['8.1.4.4(c)'],
    judge(c) {
      const rows = c.rows('sessions');
      if (!rows.length) return R('unknown', '未取到 `V$SESSIONS` 的连接分布数据。');
      const total = rows.reduce((a, r) => a + (num(col(r, 'CNT')) ?? 0), 0);
      const byIp = new Map();
      for (const r of rows) {
        const ip = String(col(r, 'CLNT_IP') ?? '').trim() || '(本机/未知)';
        byIp.set(ip, (byIp.get(ip) ?? 0) + (num(col(r, 'CNT')) ?? 0));
      }
      const top = [...byIp.entries()].sort((a, b) => b[1] - a[1])[0];
      const evidence = [...byIp.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15)
        .map(([ip, n]) => ({ 来源IP: maskIp(ip), 会话数: String(n) }));
      if (byIp.size === 1 && total > 0) {
        return R('ok', `当前 ${total} 个会话全部来自同一来源（${maskIp(top[0])}），连接来源收敛。`, { evidence });
      }
      const share = total ? Math.round((top[1] / total) * 1000) / 10 : 0;
      if (share > c.th.sessionShareWarn && total >= 5) {
        return R('warn', `连接来源过于集中：${maskIp(top[0])} 占 ${share}%（${top[1]}/${total}）。请确认该来源是否为应用服务器；若否则存在异常。`, { evidence });
      }
      return R('info', `当前 ${total} 个会话来自 ${byIp.size} 个来源（IP 已脱敏），无单一来源占绝对多数。`, { evidence });
    },
  },

  // ==================================================== L 暴露面与代码安全
  {
    id: 'expo.dangerous_exec',
    domain: 'expo',
    title: '危险包 / 过程的可执行权限',
    level: 'warn',
    priv: 'SYSDBA',
    needs: ['dangerousObjs', 'tabPrivs'],
    compliance: ['8.1.4.4(b)'],
    judge(c) {
      const objs = c.rows('dangerousObjs');
      if (!objs.length) return R('na', '本版本不存在文件读写 / 外部过程类危险包（`DBA_OBJECTS` 中未找到名单内的对象），该项不适用。');
      const names = new Set(objs.map((r) => up(col(r, 'OBJECT_NAME'))));
      const grants = c.rows('tabPrivs').filter((r) => names.has(up(col(r, 'TABLE_NAME'))) && /EXECUTE/i.test(up(col(r, 'PRIVILEGE'))));
      const toPublic = grants.filter((r) => up(col(r, 'GRANTEE')) === 'PUBLIC');
      const evidence = [
        ...objs.slice(0, 20).map((r) => ({ 类型: '对象', 名称: `${col(r, 'OWNER')}.${col(r, 'OBJECT_NAME')}`, 说明: String(col(r, 'OBJECT_TYPE') ?? '') })),
        ...grants.slice(0, 20).map((r) => ({ 类型: 'EXECUTE 授予', 名称: `${col(r, 'GRANTEE')} → ${col(r, 'OWNER')}.${col(r, 'TABLE_NAME')}`, 说明: '可执行' })),
      ];
      if (toPublic.length) {
        return R(
          'warn',
          `有 ${toPublic.length} 个危险包/过程被授予 **PUBLIC** 执行权限：这是**全体账号**都能调用的能力，提权面很大。` +
            '⚠️ **不确定性**：达梦对系统对象有大量默认授予 PUBLIC 的情况（本实例 PUBLIC 共 236 条系统对象权限），' +
            '这些包的执行权限**是否为安装默认，本插件无法区分**（插件只能看现状、看不到授权历史）。' +
            '请与全新安装的同版本环境对比确认；若确为默认且不必要，按最小权限回收。',
          {
            items: toPublic.map((r) => `PUBLIC → ${dangerousLabel(col(r, 'OWNER'), col(r, 'TABLE_NAME'))}`),
            advice: '与同版本全新安装环境对比这些 PUBLIC 执行权限；确认非默认或非必要后回收，按需授予具体账号。',
            evidence,
          },
        );
      }
      if (grants.length) {
        return R('info', `存在 ${objs.length} 个危险包/过程，其中 ${grants.length} 条 EXECUTE 授予（未授予 PUBLIC），请核对是否最小必要。`, {
          items: grants.slice(0, 12).map((r) => `${col(r, 'GRANTEE')} → ${dangerousLabel(col(r, 'OWNER'), col(r, 'TABLE_NAME'))}`),
          evidence,
        });
      }
      return R('info', `存在 ${objs.length} 个危险包/过程，未发现任何 EXECUTE 授予；能力存在但未被开放。`, { evidence });
    },
  },
  {
    id: 'expo.job_inventory',
    domain: 'expo',
    title: '作业（定时任务）清单',
    level: 'info',
    priv: 'SYSDBA',
    compliance: ['8.1.4.4(b)'],
    judge(c) {
      const err = c.errorOf('jobs');
      if (err) {
        if (/无效的表|不存在|SYSJOB|invalid|not exist|权限/i.test(String(err))) {
          return R('na', `本库不可读作业子系统 \`SYSJOB.SYSJOBS\`（${String(err).slice(0, 60)}）：未安装作业子系统或当前账号无权限，本项不适用。`);
        }
        return R('unknown', `作业清单未取到：${err}`);
      }
      const rows = c.rows('jobs');
      if (!rows.length) return R('ok', '作业子系统已安装，当前未配置任何作业（很多环境靠外部调度/备份工具，属正常）。');
      const enabled = rows.filter((r) => {
        const v = up(col(r, 'ENABLE_FLAG', 'ENABLE'));
        return v === '1' || v === 'TRUE' || v === 'Y';
      });
      const evidence = rows.slice(0, 30).map((r) => ({
        作业: String(col(r, 'NAME') ?? ''),
        启用: String(col(r, 'ENABLE_FLAG', 'ENABLE') ?? '—'),
        创建者: String(col(r, 'USERNAME') ?? '—'),
        创建时间: String(col(r, 'CREATE_TIME') ?? '—'),
      }));
      const byBiz = enabled.filter((r) => notBuiltin(col(r, 'USERNAME')));
      return R(
        'info',
        `共 ${rows.length} 个作业，其中启用 ${enabled.length} 个${byBiz.length ? `，有 ${byBiz.length} 个由非默认账号创建` : ''}。` +
          '作业是持久化执行的代码入口，请人工确认每个启用作业的用途与内容。',
        { evidence },
      );
    },
  },
  {
    id: 'expo.public_synonyms',
    domain: 'expo',
    title: 'PUBLIC 同义词',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['synonyms'],
    compliance: ['8.1.4.4(b)'],
    judge(c) {
      const rows = c.rows('synonyms');
      if (!rows.length) return R('ok', '未发现 PUBLIC 同义词。');
      const biz = rows.filter((r) => !SYSTEM_OWNERS.includes(up(col(r, 'TABLE_OWNER'))));
      const evidence = rows.slice(0, 30).map((r) => ({
        同义词: String(col(r, 'SYNONYM_NAME') ?? ''),
        指向: `${col(r, 'TABLE_OWNER') ?? '?'}.${col(r, 'TABLE_NAME') ?? '?'}`,
        目标属主: SYSTEM_OWNERS.includes(up(col(r, 'TABLE_OWNER'))) ? '系统' : '业务',
      }));
      // 真机实测本库有 403 个 PUBLIC 同义词，绝大多数指向系统对象，属达梦默认。
      if (biz.length) {
        return R('warn', `PUBLIC 同义词中，有 ${biz.length} 个指向**业务对象**（共 ${rows.length} 个）：${fmtList(biz.map((r) => col(r, 'SYNONYM_NAME')))}。全体账号可通过短名访问这些业务对象。`, {
          advice: '核对指向业务对象的 PUBLIC 同义词是否必要。',
          evidence,
        });
      }
      return R('info', `共 ${rows.length} 个 PUBLIC 同义词，**全部指向系统对象**（达梦默认的系统同义词），未发现指向业务对象的同义词。`, { evidence: evidence.slice(0, 10) });
    },
  },
  {
    id: 'expo.version_patch',
    domain: 'expo',
    title: '版本与补丁基线',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['instance'],
    compliance: ['8.1.4.4(e)'],
    judge(c) {
      const v = c.shape.version;
      const b = c.shape.build;
      if (!v) return R('unknown', '未取到数据库版本信息（`V$INSTANCE.SVR_VERSION`），无法核对补丁基线。');
      return R(
        'info',
        `数据库版本：${v}${b ? `（构建 ${b}）` : ''}；版本类型 ${c.shape.edition ?? '未取到'}${c.shape.idCode ? `，ID_CODE ${c.shape.idCode}` : ''}。` +
          '**已知漏洞修补情况需要与达梦官方补丁公告对比**——本插件不内置漏洞库（P3），请人工核对版本是否在受支持范围、是否需要升级补丁。',
        { evidence: [{ 版本: v, 构建: b ?? '—', 版本类型: c.shape.edition ?? '—', 实例: c.shape.instanceName ?? '—', 主机: c.shape.hostName ?? '—' }] },
      );
    },
  },
  {
    id: 'expo.default_pwd_risk',
    domain: 'expo',
    title: '默认口令人工核对项',
    level: 'info',
    priv: 'SYSDBA',
    needs: ['users'],
    compliance: ['8.1.4.2(b)'],
    judge(c) {
      const admins = c.users.filter((u) => u.builtin && ['SYSDBA', 'SYSSSO', 'SYSAUDITOR'].includes(u.name.toUpperCase()));
      if (!admins.length) return R('unknown', '未取到内置管理员账号记录，无法给出核对清单。');
      const evidence = admins.map((u) => ({ 账号: u.name, 状态: u.status || '—', 创建时间: u.created || '—' }));
      return R(
        'info',
        '**达梦字典中不提供「口令上次修改时间」，因此默认口令是否已修改无法自动判定**' +
          '（本插件只读，不会尝试用默认口令登录来验证）。请人工确认下列账号的默认口令已改、且未被多个环境共用：' +
          `${fmtList(admins.map((u) => u.name))}。默认口令是最常见的入侵入口，建议配合口令有效期策略强制轮换。`,
        { advice: '确认默认口令已修改；为管理员账号设置口令有效期，避免「装完就不管」。', evidence },
      );
    },
  },
];

// ==================================================== M 主机侧（OS / SSH，P2）
//
// 为什么单独一个域：等保「安全计算环境」里有一半要求**数据库内部看不见** —— 目录权限、进程运行账号、
// 监听绑定、宿主 sshd 基线、审计文件保留周期。库内参数查得再全，也回答不了「dmserver 是不是 root 跑的」。
//
// 三条纪律（与 lib/ossh.js 的命令白名单配套）：
//   ① 命令只能由 ossh.js 的命令构造器产生，这里只**读事实、做判定**；
//   ② 没配 SSH / 连不上 / 没取到事实，三者的结论必须不同（na / unknown / 正常判定），禁止裸判；
//   ③ 证据里**绝不出现口令明文** —— 明文扫描的掩码在 ossh.js 里就做了，这里只搬运。

/** 权限位：`750` → {owner:7, group:5, other:0}。 */
function modeBits(mode) {
  const m = String(mode ?? '').slice(-3).padStart(3, '0');
  return { owner: Number(m[0]), group: Number(m[1]), other: Number(m[2]) };
}
const canWrite = (d) => (Number(d) & 2) !== 0;
const canRead = (d) => (Number(d) & 4) !== 0;

/** `750（rwxr-x---）`：报告里要让人一眼看出「其他用户能不能碰」。 */
function modeText(mode) {
  const b = modeBits(mode);
  const s = (d) => `${canRead(d) ? 'r' : '-'}${canWrite(d) ? 'w' : '-'}${Number(d) & 1 ? 'x' : '-'}`;
  return `${String(mode).slice(-4)}（${s(b.owner)}${s(b.group)}${s(b.other)}）`;
}

/**
 * 主机侧检查的统一前置。三种情况必须分开：
 *   · 没配 SSH            → `na`（本次不适用，并说明怎么开）
 *   · 配了但连不上/取不到 → `unknown`（附 plink 的原始原因，绝不谎报成「没问题」）
 *   · 取到了              → 正常判定
 */
function osGate(c) {
  const o = c.os;
  if (!o) {
    return {
      na:
        '本次**未启用 OS 访问**（未提供 `sshUser` / `sshPassword`）—— 本项需要数据库主机侧数据；' +
        '补齐 SSH 参数后重跑即可（插件只执行白名单里的只读命令）。',
    };
  }
  if (o.state !== 'ok' || !o.facts) return { unknown: o.detail || '主机侧采集未返回事实数据。' };
  return { f: o.facts };
}

/** `grep` 的退出码：0=有命中，1=**无命中（扫描正常完成）**，≥2=出错。 */
const grepRanFine = (code) => code === 0 || code === 1;
/** 两条明文口令扫描（脚本 + 历史）是否都**正常跑完**（而不是「没跑/被拒」）。 */
const scansRan = (f) => grepRanFine(f.exit?.plaintext) && grepRanFine(f.exit?.history);

const OS_CHECKS = [
  {
    id: 'os.run_user',
    domain: 'os',
    title: '数据库进程的运行账号',
    level: 'crit',
    priv: null,
    needs: [],
    compliance: ['8.1.4.2(d)'],
    judge(c) {
      const g = osGate(c);
      if (g.na) return R('na', g.na);
      if (g.unknown) return R('unknown', g.unknown);
      const f = g.f;
      if (!f.primaryProcess) {
        return R('unknown', '`ps` 输出里没有定位到 dmserver 进程：可能进程名不同、或该账号看不到别的用户的进程。请人工核对 `ps -ef | grep dmserver`。', {
          evidence: [{ 命令: String(f.outputs.proc ?? '').slice(0, 300) || '(无输出)' }],
        });
      }
      const u = f.primaryProcess.user;
      const evidence = f.processes.map((p) => ({ 账号: p.user, PID: p.pid, 命令: p.cmd, 实例配置: p.iniPath ?? '—' }));
      if (u === 'root') {
        return R('crit', `数据库进程以 **root** 运行（PID ${f.primaryProcess.pid}）：数据库一旦被攻破即等同于拿到主机 root，文件权限也失去隔离意义。`, {
          advice: '改用专用 OS 账号（如 dmdba）运行：停库后以该账号启动，并把安装目录 / 数据目录属主改为该账号。',
          evidence,
        });
      }
      if (/^dm/i.test(u)) {
        return R('ok', `数据库进程以专用账号 **${u}** 运行（PID ${f.primaryProcess.pid}），符合「不用 root 运行数据库」的基线。`, { evidence });
      }
      return R('warn', `数据库进程以非专用账号 **${u}** 运行（PID ${f.primaryProcess.pid}）：建议使用仅服务于达梦的账号，便于权限隔离与责任界定。`, {
        advice: '为达梦实例单独建 OS 账号（如 dmdba），不要让数据库与其他服务共用账号。',
        evidence,
      });
    },
  },
  {
    id: 'os.dm_home_perms',
    domain: 'os',
    title: '安装 / 数据 / 审计目录权限',
    level: 'crit',
    priv: null,
    needs: [],
    compliance: ['8.1.4.2(f)'],
    judge(c) {
      const g = osGate(c);
      if (g.na) return R('na', g.na);
      if (g.unknown) return R('unknown', g.unknown);
      const f = g.f;
      const dirs = f.stat.filter((s) => f.dirPaths.includes(s.path));
      if (!dirs.length) {
        return R('unknown', '没有取到任何目录的权限（`stat` 无输出）：可能路径推导失败，或该账号无权限访问这些目录。', {
          evidence: [{ 待查路径: f.dirPaths.join('、') || '—', stat输出: String(f.outputs.perms ?? '').slice(0, 200) || '(无输出)' }],
        });
      }
      const evidence = dirs.map((s) => ({
        路径: s.path,
        类型: s.path === f.dmHome ? '安装目录' : '数据/配置目录',
        权限: modeText(s.mode),
        属主: `${s.owner}:${s.group}`,
      }));
      const otherWrite = dirs.filter((s) => canWrite(modeBits(s.mode).other));
      const groupWrite = dirs.filter((s) => canWrite(modeBits(s.mode).group));
      /**
       * ★ 分级要点（真机校准）：安装目录 755 是**达梦厂商默认**，判成警告会天天误报（狼来了）；
       *   而数据/配置目录对 others 可读是实打实的暴露。所以同一个「其他人可读」，
       *   在安装目录上只算**提示**，在数据/配置目录上算**警告**。
       */
      const otherReadData = dirs.filter((s) => s.path !== f.dmHome && canRead(modeBits(s.mode).other));
      const otherReadHome = dirs.filter((s) => s.path === f.dmHome && canRead(modeBits(s.mode).other));
      if (otherWrite.length) {
        return R('crit', `有 ${otherWrite.length} 个目录**其他用户可写**：任何人都能改写数据文件、配置或审计文件，等于绕开数据库的全部权限控制。`, {
          advice: '`chmod o-w <目录>`；数据 / 配置 / 审计目录建议 750（属主 dmdba、组 dinstall），不要对 others 开放写权限。',
          evidence,
        });
      }
      if (groupWrite.length || otherReadData.length) {
        const items = [
          ...groupWrite.map((s) => `${s.path}：同组用户可写（${modeText(s.mode)}）`),
          ...otherReadData.map((s) => `${s.path}：其他用户可读（${modeText(s.mode)}），数据与配置可被直接读走`),
        ];
        return R('warn', `目录权限存在可收敛项：${groupWrite.length} 个同组可写、${otherReadData.length} 个数据/配置目录对其他用户可读。`, {
          advice: '数据 / 配置 / 审计目录建议 750 或 700（`chmod 750 <数据目录>`）；安装目录至少去掉 others 的写权限。',
          items,
          evidence,
        });
      }
      if (otherReadHome.length) {
        return R('info', `安装目录（${otherReadHome.map((s) => s.path).join('、')}）对其他用户可读 —— 这是达梦厂商默认权限，**不算缺陷**；数据 / 配置目录均未对 others 开放读写。`, {
          advice: '可选加固：`chmod 750 <DM_HOME>`（把组属主设为安装组，别影响升级与补丁）。',
          evidence,
        });
      }
      return R('ok', `已核对的 ${dirs.length} 个目录均未被同组或其他用户写入，且数据 / 配置目录未对 others 开放读权限。`, { evidence });
    },
  },
  {
    id: 'os.config_file_perms',
    domain: 'os',
    title: '配置文件权限（dm.ini 等）',
    level: 'warn',
    priv: null,
    needs: [],
    compliance: ['8.1.4.2(f)'],
    judge(c) {
      const g = osGate(c);
      if (g.na) return R('na', g.na);
      if (g.unknown) return R('unknown', g.unknown);
      const f = g.f;
      const files = f.stat.filter((s) => f.filePaths.includes(s.path));
      if (!files.length) {
        return R('unknown', '没有取到任何配置文件的权限（文件可能不存在，或 `stat` 无输出）。', {
          evidence: [{ 待查文件: f.filePaths.join('、') || '—' }],
        });
      }
      const evidence = files.map((s) => ({ 文件: s.path, 权限: modeText(s.mode), 属主: `${s.owner}:${s.group}` }));
      const loose = files.filter((s) => canRead(modeBits(s.mode).other) || canWrite(modeBits(s.mode).other));
      if (loose.length) {
        return R('warn', `有 ${loose.length} 个配置文件对**其他用户**开放了权限：\`dm.ini\` 含实例路径、内存与端口配置，\`dmdcr.ini\` / \`dmarch.ini\` 还含集群拓扑与归档路径，不该让无关账号读到。`, {
          advice: '配置文件建议 640 或 600、属主为数据库 OS 账号：`chmod 640 dm.ini`。',
          evidence,
        });
      }
      return R('ok', `${files.length} 个配置文件（含 dm.ini）未对 others 开放读写权限。`, { evidence });
    },
  },
  {
    id: 'os.listen_binding',
    domain: 'os',
    title: '实例监听的绑定范围',
    level: 'warn',
    priv: null,
    needs: [],
    compliance: ['8.1.4.4(b)', '8.1.4.4(c)'],
    judge(c) {
      const g = osGate(c);
      if (g.na) return R('na', g.na);
      if (g.unknown) return R('unknown', g.unknown);
      const f = g.f;
      const port = f.dbPort;
      const evidence = [
        { 项: '本次评估的实例端口', 值: String(port ?? '未取到') },
        { 项: 'LISTEN_IP 参数（库内）', 值: String(c.pv('LISTEN_IP') ?? '未取到') },
        // 进程名一并进证据（`ss -lntp` 取到才有）—— 读者据此判断「这条监听项是哪个服务」
        ...f.listen.slice(0, 20).map((l) => ({ 项: '监听项', 值: `${l.addr}:${l.port}${l.proc ? `（${l.proc}）` : ''}` })),
      ];
      if (!f.listen.length) {
        return R('unknown', '`ss` 与 `netstat` 都没有输出监听项：该账号可能看不到 socket 列表，需人工核对 `ss -lntp`。', { evidence });
      }
      const hit = f.listen.filter((l) => (port ? l.port === Number(port) : true));
      if (port && !hit.length) {
        return R('unknown', `监听列表里没有看到实例端口 ${port}：可能实例未运行、端口被改，或该账号看不到该 socket。`, { evidence });
      }
      /** 真机（DSC）实测监听项就是 `*:7236`（裸星号）：直接嵌进 `**…**` 会渲染成 `*****`，得说人话。 */
      const addrLabel = (a) =>
        ['0.0.0.0', '*'].includes(a) ? `${a}（所有 IPv4 网卡）` : ['::', '[::]'].includes(a) ? `${a}（所有 IPv6 网卡）` : a;
      /**
       * ★ DMDSC：一台主机上**不止一个达梦服务在听**。只判数据库端口会漏掉集群特有的那几项
       *   （真机实测 `10.0.0.61`：7236/7336 `dmserver`、7436/7536 `dmasmsvrm`、7936 `dmcss`、
       *   4236 `dmap`，全部绑 `*`）。所以按**进程名**把达梦家族的监听项一并挑出来判。
       *   进程名取不到（非 root，或该机器不支持 `-p`）→ 退回旧行为：只判数据库端口。
       */
      const dmShare = f.listen.filter((l) => l.proc && DM_LISTEN_PROC.test(l.proc));
      if (dmShare.length === 0) {
        // 旧路径（拿不到进程名）：只能判数据库端口 —— 顺带修掉文案里写死的 5236
        const wide0 = hit.filter((l) => WILDCARD_ADDR.test(l.addr));
        if (wide0.length) {
          return R('warn', `实例端口 ${port ?? ''} 监听在「${[...new Set(wide0.map((l) => addrLabel(l.addr)))].join('、')}」：对所有网卡开放，任何能路由到主机的地址都可尝试连接（配合弱口令即成入侵面）。`, {
            advice: '把 `LISTEN_IP` 收到业务网段地址（或只监听内网网卡），并用防火墙 / 安全组限制实例端口的来源。',
            evidence,
          });
        }
        return R('ok', `实例端口 ${port ?? ''} 只监听在具体地址（${[...new Set(hit.map((l) => l.addr))].join('、')}），未对所有网卡开放。`, { evidence });
      }
      const wide = dmShare.filter((l) => WILDCARD_ADDR.test(l.addr));
      const desc = (l) => `\`${l.proc}\`:${l.port}（${DM_LISTEN_ROLE[String(l.proc).toLowerCase()] ?? '达梦服务'}）`;
      // 地址去重：多个服务端口通常绑在**同一个**通配地址上，逐个打印会变成一串一模一样的 `*（所有 IPv4 网卡）`
      const addrSet = (arr) => [...new Set(arr.map((l) => addrLabel(l.addr)))].join('、');
      if (wide.length) {
        return R(
          'warn',
          `达梦服务共 **${dmShare.length}** 个监听端口，其中 **${wide.length}** 个绑在「${addrSet(wide)}」：` +
            `${wide.map(desc).join('、')}。集群 / 共享存储相关服务对全网卡开放，任何能路由到主机的地址都可尝试连接（配合弱口令即成入侵面）。`,
          {
            advice:
              '把 `LISTEN_IP` 收到业务网段地址，并用防火墙 / 安全组限制达梦各服务端口的来源 —— ' +
              'DMDSC 上除实例端口外还有 `dmcss`（集群同步）、`dmasmsvrm`（ASM）、`dmap`（助手）。',
            evidence,
          },
        );
      }
      return R(
        'ok',
        `达梦服务 ${dmShare.length} 个监听端口（${dmShare.map(desc).join('、')}）都只监听在具体地址，未对所有网卡开放。`,
        { evidence },
      );
    },
  },
  {
    id: 'os.plaintext_credential',
    domain: 'os',
    title: '明文口令痕迹（脚本 / 历史）',
    level: 'warn',
    priv: null,
    needs: [],
    compliance: ['8.1.4.8(b)', '8.1.4.1(a)'],
    judge(c) {
      const g = osGate(c);
      if (g.na) return R('na', g.na);
      if (g.unknown) return R('unknown', g.unknown);
      const f = g.f;
      const fileHits = f.plaintextHits ?? [];
      const histHits = f.historyHits ?? [];
      const evidence = [
        { 项: '扫描范围（安装目录）', 值: f.dmHome ?? '未取到' },
        { 项: '扫描范围（历史文件）', 值: `${f.homeDir ?? '—'}/.bash_history` },
        { 项: '脚本 / ini 命中', 值: String(fileHits.length) },
        { 项: '历史命中', 值: String(histHits.length) },
      ];
      const items = [
        ...fileHits.slice(0, 10).map((h) => `${h.file}${h.lineno ? `:${h.lineno}` : ''} → ${h.snippet}`),
        ...histHits.slice(0, 5).map((h) => `~/.bash_history${h.lineno ? `:${h.lineno}` : ''} → ${h.snippet}`),
      ];
      if (items.length) {
        const total = fileHits.length + histHits.length;
        // 真机教训：扫描上限（现在是 200）一到就会低报规模，所以到顶时必须说明，而不是给个假精确数
        const capped = fileHits.length >= 200 || histHits.length >= 200;
        return R(
          'warn',
          `在安装目录与运行账号的 shell 历史里发现 ${capped ? '至少 ' : ''}${total} 处**明文口令连接串**` +
            `（形如 \`disql 账号/口令@主机\`，片段已掩码）${total > items.length ? `，下列只列前 ${items.length} 条` : ''}` +
            `${capped ? '；已达到单次扫描上限 200 条，实际可能更多' : ''}：` +
            '明文口令会让任何能读这些文件的账号直接拿到数据库凭据，且改口令后常忘记同步，形成长期后门。',
          {
            advice:
              '把口令从脚本与历史里移出：改用交互输入、受保护的凭据文件（600 权限）或操作系统认证；' +
              '并清理 shell 历史里的带口令命令（注意：**已登录的 shell 在退出时会用内存里的历史回写**，' +
              '所以要么在各会话里执行 `history -c && history -r ~/.bash_history`，要么等会话全部退出后再清）。' +
              '本项按 `disql`/`dmrman` 连接串形态扫描，应用配置（如 JDBC 属性文件里的 `user:pass@`）需另行核对。',
            items,
            evidence,
          },
        );
      }
      if (!f.outputs.plaintext && !f.outputs.history && !scansRan(f)) {
        return R('unknown', '明文口令扫描没有产生任何输出，且两条命令都没正常返回（命令未执行或被拒），无法判定。', { evidence });
      }
      return R('ok', `已扫描安装目录（${f.dmHome ?? '—'}）与运行账号的 shell 历史（${f.homeDir ?? '—'}/.bash_history）：没有发现 \`disql\`/\`dmrman\` 形态的明文口令连接串。`, {
        evidence,
        advice: '本项只覆盖上述两个范围、且只认 `disql`/`dmrman` 连接串形态；备份脚本、监控脚本放在别处，或凭据写在应用配置里时需另行核对。',
      });
    },
  },
  {
    id: 'os.audit_retention',
    domain: 'os',
    title: '审计文件保留周期（OS 侧）',
    level: 'warn',
    priv: null,
    needs: [],
    compliance: ['8.1.4.3(c)'],
    judge(c) {
      const g = osGate(c);
      if (g.na) return R('na', g.na);
      if (g.unknown) return R('unknown', g.unknown);
      const f = g.f;
      const r = f.retention ?? null;
      if (!f.auditDir) {
        return R('unknown', '无法定位审计目录（没从进程信息推出实例路径），需人工核对 `<实例目录>/audit`。');
      }
      const evidence = [
        { 项: '审计目录', 值: f.auditDir },
        { 项: '文件数', 值: String(f.auditFiles.length) },
        { 项: '最旧 / 最新', 值: r?.oldest ? `${r.oldest.date} / ${r.newest.date}` : '—' },
        { 项: '要求保留期', 值: `${f.retentionDays} 天（可用 osRetentionDays 调整）` },
      ];
      if (!f.auditFiles.length) {
        // `find` 在目录不存在时返回 1（无输出）——这与「命令没跑」不同，得用退出码区分
        if (!grepRanFine(f.exit?.audit)) {
          return R('unknown', `审计目录探测没有正常返回（exit=${f.exit?.audit ?? '未知'}）：命令未执行或被拒，无法判定。`, { evidence });
        }
        return R('warn', `审计目录 \`${f.auditDir}\` 不存在或为空：DM 只在启用审计后才创建该目录，这多半意味着审计未开启（库内 \`ENABLE_AUDIT\` 为 0），也可能审计文件放在别处。`, {
          advice: '先确认库内审计已开启；开启后按要求的保留期规划审计文件上限与归档。',
          evidence,
        });
      }
      if (r.state === 'short') {
        return R(
          'warn',
          `最旧的审计文件只到 ${r.oldest.date}（距今约 ${r.ageDays} 天），**短于要求的 ${f.retentionDays} 天**：更早的审计记录已被滚动掉，需要追溯历史操作时拿不出证据。`,
          {
            advice: `调大审计文件上限或改用外部归档，保证至少能回溯 ${f.retentionDays} 天；\`AUDIT_FILE_FULL_MODE\` 的写满策略（覆盖还是报错）要一并确认。`,
            evidence,
          },
        );
      }
      return R('ok', `审计目录内最旧文件 ${r.oldest.date}（约 ${r.ageDays} 天），达到要求的 ${f.retentionDays} 天保留期。`, { evidence });
    },
  },
  {
    id: 'os.sshd_baseline',
    domain: 'os',
    title: '宿主 SSH 服务基线',
    level: 'crit',
    priv: null,
    needs: [],
    compliance: ['8.1.4.4(b)', '8.1.4.1(c)'],
    judge(c) {
      const g = osGate(c);
      if (g.na) return R('na', g.na);
      if (g.unknown) return R('unknown', g.unknown);
      const f = g.f;
      const keys = Object.keys(f.sshd ?? {});
      if (!keys.length) {
        return R('unknown', '没有读到 `/etc/ssh/sshd_config` 的相关配置（文件不存在、路径不同，或该账号无读权限）。', {
          evidence: [{ 命令: 'grep -Ei PermitRootLogin|PasswordAuthentication|… /etc/ssh/sshd_config' }],
        });
      }
      const evidence = keys.map((k) => ({ 配置项: k, 值: f.sshd[k] }));
      const items = [];
      const hard = [];
      const soft = [];
      const rootLogin = String(f.sshd.permitrootlogin ?? '').toLowerCase();
      if (rootLogin === 'yes') hard.push('`PermitRootLogin yes`：允许 root 直接 SSH 登录，暴力破解的收益最大');
      const empty = String(f.sshd.permitemptypasswords ?? '').toLowerCase() === 'yes';
      if (empty) hard.push('`PermitEmptyPasswords yes`：允许空口令登录');
      if (String(f.sshd.protocol ?? '') === '1') hard.push('`Protocol 1`：SSHv1 已不安全');
      /**
       * ★ 为什么把「允许口令认证」单列成**提示**而不是警告：很多单位就是靠口令 SSH 运维，
       *   把它判成「不符合」会天天误报（狼来了）。它属**加固建议**（改用密钥 / 堡垒机 + 限来源），
       *   所以只在没有硬性问题时给 `info`，不参与「最重结论」的告警。
       */
      if (String(f.sshd.passwordauthentication ?? '').toLowerCase() === 'yes') {
        soft.push('`PasswordAuthentication yes`：允许口令认证（加固建议：专网内改用密钥 / 堡垒机，并限制来源地址）');
      }
      if (hard.length) {
        return R(empty ? 'crit' : 'warn', `宿主 SSH 基线有 ${hard.length} 处高危偏离：${hard.length === 1 ? hard[0] : '见下列条目'}。数据库主机被 SSH 攻破等于数据库被攻破，这条要与其他项同等看待。`, {
          advice: '`PermitRootLogin no`、`PermitEmptyPasswords no`；生产库建议只允许密钥认证并经堡垒机跳转。',
          items: [...hard, ...soft],
          evidence,
        });
      }
      if (soft.length) {
        return R('info', `宿主 SSH 未见高危配置（未允许 root 直登、未允许空口令）；仅有一条加固建议。`, {
          advice: '如条件允许，把 SSH 收敛到「密钥认证 + 堡垒机 + 来源限制」。',
          items: soft,
          evidence,
        });
      }
      return R('ok', '宿主 SSH 基线未见高危配置（未允许 root 直登、未允许空口令）。', { evidence });
    },
  },
];

CHECKS.push(...OS_CHECKS);
