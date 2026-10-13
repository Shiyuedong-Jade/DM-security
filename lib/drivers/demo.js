/**
 * 演示驱动（`driver=demo`）：内置样例数据，**不连库**。
 *
 * 存在的理由（DESIGN §5.4）：
 *   · 没有达梦环境的机器上也能自检、演示与回归；
 *   · 自检脚本要能断言「每种结论分支都被覆盖」。
 *
 * ★ 本样例的形态由 **2026-10-12 在 10.0.0.40 真机实测**校正过：
 *   · 用户账号名用 `SYSSSO`（三个 S）、认证方式用真机取值 `NDCT_DB_AUTHENT`；
 *   · `pwdPolicy` 用**真机的 `SYSUSERS` 列名**（SESS_PER_USER / REUSE_MAX / ALLOW_ADDR /
 *     LAST_LOGIN_DTID …），不再是猜的 `SESSION_PER_USER` / `CPU_PER_SESSION`；
 *   · `profiles`（DBA_PROFILES）**刻意做成权限不足**，用来复现「受限账号采集」时
 *     CPU/内存/资源限制项判「未取到」的真实分支（这正是真机上 appuser 账号的处境）；
 *   · 版本类型用权威的 `V$INSTANCE.ID_CODE` 解码（企业版 → MAC 判「不适用」）。
 *
 * 所有值都是**构造的示例**，不对应任何真实系统。
 */

const OK = (columns, rows) => ({ columns, rows, error: null, truncated: false });
const ERR = (msg) => ({ columns: null, rows: [], error: msg, truncated: false });

/** 参数快照。**故意不含** PRIV_FLAG（企业版本就没有 → 三权分立判「不适用」）。 */
const PARAMS = [
  ['ENABLE_AUDIT', '0', '1', '0', '2', '1', '审计开关：0=关闭，1=普通审计，2=普通审计+实时审计'],
  ['AUDIT_MAX_FILE_SIZE', '0', '100', '0', '2048', '100', '单个审计文件大小上限'],
  ['AUDIT_FILE_FULL_MODE', '0', '3', '0', '1', '3', '审计文件写满后的处理方式'],
  ['SVR_LOG', '0', '0', '0', '1', '0', '是否启用 SQL 日志'],
  ['PWD_POLICY', '3', '15', '0', '31', '15', '口令策略位掩码'],
  ['PWD_MIN_LEN', '6', '8', '1', '48', '8', '口令最小长度'],
  ['ENABLE_LOCAL_OSAUTH', '1', '1', '0', '1', '0', '本地操作系统认证'],
  ['ENABLE_REMOTE_OSAUTH', '0', '0', '0', '1', '0', '远程操作系统认证'],
  ['ENABLE_ENCRYPT', '0', '0', '0', '1', '0', '通信加密开关'],
  ['GRANT_SCHEMA', '0', '0', '0', '1', '0', '是否允许按模式授权'],
  ['MAX_SESSIONS', '1500', '1500', '1', '10000', '100', '最大并发会话数'],
];

/** 用户清单。真机结论：安全员是 SYSSSO；数据库口令认证的取值是 NDCT_DB_AUTHENT。 */
const USERS = [
  ['SYS', 0, 'OPEN', 'SYSTEM', 'NDCT_DB_AUTHENT', null, null, '2020-01-01 00:00:00'],
  ['SYSDBA', 1, 'OPEN', 'SYSTEM', 'NDCT_DB_AUTHENT', null, null, '2020-01-01 00:00:00'],
  ['SYSAUDITOR', 2, 'OPEN', 'SYSTEM', 'NDCT_DB_AUTHENT', null, null, '2020-01-01 00:00:00'],
  ['SYSSSO', 3, 'LOCKED', 'SYSTEM', 'NDCT_DB_AUTHENT', '2020-01-01 00:00:00', null, '2020-01-01 00:00:00'],
  ['APP_USER', 100, 'OPEN', 'DMAPP', 'NDCT_DB_AUTHENT', null, null, '2023-03-11 09:20:31'],
  ['DEV_USER', 101, 'OPEN', 'DMAPP', 'NDCT_DB_AUTHENT', null, '2027-03-11 09:20:31', '2023-05-02 14:02:10'],
  ['REPORT_USER', 102, 'OPEN', 'DMAPP', 'NDCT_DB_AUTHENT', null, '2027-01-01 00:00:00', '2023-06-18 10:11:00'],
  ['OLD_USER', 103, 'EXPIRED', 'DMAPP', 'NDCT_DB_AUTHENT', null, '2024-12-31 00:00:00', '2021-08-01 08:00:00'],
];

/**
 * 逐账号口令策略/资源限制 —— **真机列名形态**。
 * 列序：USERNAME, PWD_POLICY, LIFE_TIME, FAILED_NUM, FAILED_ATTEMPS, LOCK_TIME,
 *       CONN_IDLE_TIME, SESS_PER_USER, REUSE_MAX, REUSE_TIME,
 *       ALLOW_ADDR, NOT_ALLOW_ADDR, ALLOW_DT, LAST_LOGIN_DTID, LAST_LOGIN_IP
 */
const PWD_ROWS = [
  ['SYSDBA', 31, 0, 0, 0, 0, 0, 0, 0, 0, null, null, null, '2026-10-10 09:12:53', '::1'],
  ['SYSAUDITOR', 31, 0, 0, 0, 0, 0, 0, 0, 0, null, null, null, null, null],
  ['SYSSSO', 31, 0, 0, 0, 0, 0, 0, 0, 0, null, null, null, null, null],
  // 从未登录 + 口令永不过期 + 未限制会话数/口令重用
  ['APP_USER', 3, 0, 0, 0, 0, 0, 0, 0, 0, null, null, null, null, null],
  ['DEV_USER', 31, 365, 5, 5, 1, 30, 5, 5, 30, '10.0.0.0/24', null, null, '2026-09-01 08:00:00', '10.0.0.50'],
  ['REPORT_USER', 31, 90, 5, 2, 10, 30, 5, 5, 30, null, null, '2026-10-01 09:00:00 TO 2026-10-31 18:00:00', '2025-12-01 10:00:00', '10.0.0.51'],
  ['OLD_USER', 31, 90, 5, 0, 10, 30, 0, 5, 30, null, null, null, '2024-06-01 09:00:00', '10.0.0.52'],
];

const DEMO = {
  instance: OK(
    ['INSTANCE_NAME', 'HOST_NAME', 'STATUS$', 'MODE$', 'SVR_VERSION', 'BUILD_VERSION'],
    // 取值对齐真机：SVR_VERSION 是长串（不含四段号），BUILD_VERSION 与 ID_CODE 同串（ID_CODE 仅多前缀 --）
    [['DMSERVER', 'dm-host-01', 'OPEN', 'NORMAL', 'DM Database Server x64 V8', '03134284604-20260707-335949-20228']],
  ),
  // ROLE$ 用达梦的真实码值（0=NORMAL / 1=PRIMARY / 2=STANDBY），ARCH_MODE 'Y'=归档
  database: OK(['NAME', 'DSC_NODES', 'ARCH_MODE', 'ROLE$', 'STATUS$'], [['DMAPP', '1', 'Y', '0', 'OPEN']]),
  dwApply: OK(['CNT'], [['0']]),
  dwSend: OK(['CNT'], [['0']]),
  dscEp: OK(['EP_NAME', 'EP_MODE', 'EP_STATUS'], []),
  // 真机判据：版本类型由 ID_CODE 解码，企业版 → 强制访问控制判「不适用」
  // INNER_VERSION 是四位内核版本号，由 ID_CODE 解出（取法同 02 组 basic.build）
  buildType: OK(['ID_CODE', 'BUILD_TYPE', 'INNER_VERSION'], [['--03134284604-20260707-335949-20228', '企业版', '8.1.5.60']]),
  // 版本与实例信息（对齐 02 组「基础信息」一组的取法）
  instanceRuntime: OK(
    ['INSTANCE_NAME', 'START_TIME', 'RUN_DAYS', 'RUN_MINUTES'],
    [['DMSERVER', '2026-09-01 08:30:00', '41.05', '59112.0']],
  ),
  charset: OK(
    ['UNICODE_FLAG', 'CASE_SENSITIVE', 'EXTENT_SIZE', 'PAGE_SIZE_BYTES'],
    [['1', '1', '16', '8192']],
  ),
  // 授权剩余天数刻意取 45 天（落在 30~90 的提醒区间），用于展示授权到期的视觉提醒
  license: OK(
    ['SERIES_NO', 'SERVER_SERIES', 'SERVER_TYPE', 'SERVER_VER', 'EXPIRED_DATE', 'AUTHORIZED_CUSTOMER', 'MAX_CPU_NUM', 'DAYS_LEFT'],
    [['DMSERVER-ENT', 'DM8 企业版', '企业版', '通配（授权文件为 X.X.x.x）', '2026-11-26', '某某单位', '32', '45']],
  ),
  params: OK(['PARA_NAME', 'PARA_VALUE', 'FILE_VALUE', 'MIN_VALUE', 'MAX_VALUE', 'DEFAULT_VALUE', 'DESCRIPTION'], PARAMS),
  users: OK(
    ['USERNAME', 'USER_ID', 'ACCOUNT_STATUS', 'DEFAULT_TABLESPACE', 'AUTHENTICATION_TYPE', 'LOCK_DATE', 'EXPIRY_DATE', 'CREATED_AT'],
    USERS,
  ),
  // 刻意保留「降级形态」：模拟本版本 DBA_USERS 不含访问路径列 ——
  // 此时检查项会退回 pwdPolicy（同一张 SYSUSERS）取 ALLOW_ADDR，这条回退路径本身要被测到。
  userAccess: OK(['USERNAME', 'ACCOUNT_STATUS'], USERS.map((u) => [u[0], u[2]])),
  pwdPolicy: OK(
    ['USERNAME', 'PWD_POLICY', 'LIFE_TIME', 'FAILED_NUM', 'FAILED_ATTEMPS', 'LOCK_TIME', 'CONN_IDLE_TIME', 'SESS_PER_USER', 'REUSE_MAX', 'REUSE_TIME', 'ALLOW_ADDR', 'NOT_ALLOW_ADDR', 'ALLOW_DT', 'LAST_LOGIN_DTID', 'LAST_LOGIN_IP'],
    PWD_ROWS,
  ),
  rolePrivs: OK(
    ['GRANTEE', 'GRANTED_ROLE', 'ADMIN_OPTION'],
    [
      ['SYSDBA', 'DBA', 'Y'],
      ['SYSDBA', 'DB_AUDIT_ADMIN', 'Y'],
      ['SYSAUDITOR', 'DB_AUDIT_ADMIN', 'N'],
      ['SYSSSO', 'DB_POLICY_ADMIN', 'N'],
      ['APP_USER', 'DBA', 'N'],
      ['APP_USER', 'RESOURCE', 'N'],
      ['DEV_USER', 'RESOURCE', 'N'],
      ['REPORT_USER', 'RESOURCE', 'N'],
    ],
  ),
  sysPrivs: OK(
    ['GRANTEE', 'PRIVILEGE', 'ADMIN_OPTION'],
    [
      ['SYSDBA', 'GRANT ANY PRIVILEGE', 'N'],
      ['APP_USER', 'ALTER USER', 'N'],
      ['APP_USER', 'CREATE USER', 'N'],
      ['DEV_USER', 'SELECT ANY TABLE', 'N'],
      ['PUBLIC', 'SELECT TABLE', 'N'],
      ['PUBLIC', 'EXECUTE PACKAGE', 'N'],
      ['PUBLIC', 'GRANT SCHEMA', 'N'],
    ],
  ),
  tabPrivs: OK(
    ['GRANTEE', 'OWNER', 'TABLE_NAME', 'PRIVILEGE', 'GRANTABLE'],
    [
      ['PUBLIC', 'SYS', 'UTL_FILE', 'EXECUTE', 'N'],
      ['PUBLIC', 'SYS', 'ALL_TABLES', 'SELECT', 'N'],
      ['PUBLIC', 'DMAPP', 'T_DICT', 'SELECT', 'N'],
      ['APP_USER', 'DMAPP', 'T_ORDER', 'SELECT', 'N'],
      ['REPORT_USER', 'DMAPP', 'V_REPORT', 'SELECT', 'N'],
    ],
  ),
  roles: OK(
    ['ROLE', 'PASSWORD_REQUIRED', 'AUTHENTICATION_TYPE'],
    [
      ['DBA', null, null],
      ['PUBLIC', null, null],
      ['RESOURCE', null, null],
      ['SOI', null, null],
      ['VTI', null, null],
      ['SYS_ADMIN', null, null],
      ['DB_AUDIT_ADMIN', null, null],
      ['DB_POLICY_ADMIN', null, null],
      ['ROLE_APP', null, null],
    ],
  ),
  // 受限账号（非 SYSDBA）采集时读不到 DBA_PROFILES —— 复现真机上 appuser 的处境
  profiles: ERR('没有[DBA_PROFILES]对象的查询权限'),
  auditRecords: OK(['N'], [['0']]),
  auditDict: OK(
    ['OWNER', 'OBJECT_NAME', 'OBJECT_TYPE'],
    [['SYSAUDITOR', 'V$AUDITRECORDS', 'VIEW'], ['SYS', 'AUD$', 'TABLE']],
  ),
  sessions: OK(
    ['USER_NAME', 'APPNAME', 'CLNT_IP', 'STATE', 'CNT'],
    [
      ['APP_USER', 'DMAPP.EXE', '10.0.0.50', 'ACTIVE', '210'],
      ['APP_USER', 'DMAPP.EXE', '10.0.0.51', 'IDLE', '180'],
      ['SYSDBA', 'disql', '10.0.0.40', 'ACTIVE', '22'],
    ],
  ),
  jobs: OK(
    ['ID', 'NAME', 'ENABLE_FLAG', 'USERNAME', 'CREATE_TIME'],
    [[1001, 'JOB_NIGHT_BACKUP', '1', 'SYSDBA', '2024-01-11 02:00:00'], [1002, 'JOB_PURGE_ARCH', '0', 'APP_USER', '2024-02-02 03:00:00']],
  ),
  dangerousObjs: OK(
    ['OWNER', 'OBJECT_NAME', 'OBJECT_TYPE', 'STATUS'],
    [['SYS', 'UTL_FILE', 'PACKAGE', 'VALID'], ['SYS', 'DBMS_LOB', 'PACKAGE', 'VALID'], ['SYS', 'DBMS_SCHEDULER', 'PACKAGE', 'VALID']],
  ),
  synonyms: OK(
    ['OWNER', 'SYNONYM_NAME', 'TABLE_OWNER', 'TABLE_NAME'],
    [['PUBLIC', 'SYN_ORDER', 'DMAPP', 'T_ORDER'], ['PUBLIC', 'ALL_USERS', 'SYS', 'ALL_USERS']],
  ),
  encObjs: OK(['OWNER', 'OBJECT_NAME', 'OBJECT_TYPE'], []),
  // 表列加密元数据（真机实测本版本有 DBA_ENCRYPTED_COLUMNS；样例取 0 列 = 未启用列加密）
  encColumns: OK(['N'], [['0']]),
  encColumnList: OK(['OWNER', 'TABLE_NAME', 'COLUMN_NAME'], []),
  macObjs: OK(['OWNER', 'OBJECT_NAME', 'OBJECT_TYPE'], []),
};

/**
 * 演示驱动的查询执行：形状与 `bridge.runQueries` 完全一致。
 *
 * @param {Array} queries
 * @param {{dsc?:boolean, variant?:number}} [opts]
 *   `dsc`     造一套 DMDSC 双节点样例（`DSC_NODES=2` + 两个节点名）
 *   `variant` 1 = **第二节点**：审计已开（`ENABLE_AUDIT=1`）、本地 OS 认证已关（`=0`）、主机名不同
 *             —— 用来离线复现「节点间配置漂移」这一 DSC 专有问题
 */
export async function runDemoQueries(queries, opts = {}) {
  const { dsc = false, variant = 0 } = opts;
  const data = { ...DEMO };
  if (dsc) {
    data.database = OK(['NAME', 'DSC_NODES', 'ARCH_MODE', 'ROLE$', 'STATUS$'], [['DMAPP', '2', 'Y', '0', 'OPEN']]);
    // 节点名与 EP_MODE 用**真机实测取值**（2026-10-12，DSC 双节点）：
    // V$DSC_EP_INFO 列为 EP_NAME/EP_SEQNO/EP_GUID/EP_TIMESTAMP/EP_MODE/EP_STATUS，**不含地址列**；
    // EP_MODE 实值为 `Control Node` / `Normal Node`（不是 MASTER/SLAVE）。
    data.dscEp = OK(
      ['EP_NAME', 'EP_SEQNO', 'EP_GUID', 'EP_TIMESTAMP', 'EP_MODE', 'EP_STATUS'],
      [
        ['DSC01', '0', '107178', '967163', 'Control Node', 'OK'],
        ['DSC02', '1', '112747', '917012', 'Normal Node', 'OK'],
      ],
    );
  }
  if (variant === 1) {
    const patch = { ENABLE_AUDIT: '1', ENABLE_LOCAL_OSAUTH: '0' };
    data.params = OK(
      DEMO.params.columns,
      PARAMS.map((r) => (patch[r[0]] === undefined ? r : [r[0], patch[r[0]], patch[r[0]], ...r.slice(3)])),
    );
    data.instance = OK(
      DEMO.instance.columns,
      [['DMSERVER', 'dm-host-02', 'OPEN', 'NORMAL', 'DM Database Server x64 V8', '03134284604-20260707-335949-20228']],
    );
  }
  const out = {};
  for (const q of queries) {
    const hit = data[q.key];
    if (hit) out[q.key] = { ...hit, sqlUsed: q.sql };
    else out[q.key] = { columns: null, rows: [], error: `DEMO_NO_DATA(${q.key})`, sqlUsed: q.sql };
  }
  return out;
}

/** 供报告与自检引用：演示数据的形态摘要。 */
export const DEMO_SHAPE = {
  instanceName: 'DMSERVER',
  hostName: 'dm-host-01',
  dbName: 'DMAPP',
  version: '8.1.3.100',
  edition: '企业版（由 ID_CODE 解码，非安全版 → MAC 不适用）',
  note: 'profiles 刻意做成权限不足，用于复现受限账号采集时的「未取到」分支',
};

/**
 * 主机侧（OS / SSH）演示数据。
 *
 * 为什么样例要分两套：主机侧的判定分支（root 运行 / 目录 other 可写 / 监听全网卡 / 明文口令 / 审计目录空）
 * 在真机上不容易一次凑齐，而**离线自检必须能覆盖**。约定与 JDBC 侧一致：
 *   · `dsc*` 或普通 host → 节点 1：配置规范（专用账号 750、只监听具体 IP、无明文口令、审计文件在）
 *   · host 以 `2` 结尾   → 节点 2：故意做坏（root 运行、目录 777、监听 0.0.0.0、脚本里有口令、审计目录空）
 * 这样 `targets: 'dsc-node1:7236,dsc-node2:7237'` 一条演示命令就能同时看到「合规」与「严重」两条路。
 *
 * ⚠️ 明文口令那句是**构造的假口令**（`Demo#Passw0rd!`，与任何真实环境无关），用来验证「掩码在源头生效」——
 * 自检会断言它**不可能**出现在任何结论对象或报告里，另有一条守卫扫描整个包、禁止出现已知的真机口令。
 */
export function demoOsOutputs({ variant = 0 } = {}) {
  const user = variant === 1 ? 'root' : 'dmdba';
  const inst = variant === 1 ? '/opt/dmdbms/data/DAMENG' : '/home/dmdba/dmdbms/data/DAMENG';
  const home = variant === 1 ? '/opt/dmdbms' : '/home/dmdba/dmdbms';
  const proc = `${user} ${variant === 1 ? 4711 : 4321} ${home}/bin/dmserver ${inst}/dm.ini -noconsole`;
  const perms = [
    variant === 1 ? `777 root:root ${home}` : `750 dmdba:dinstall ${home}`,
    variant === 1 ? `777 root:root ${home}/data` : `750 dmdba:dinstall ${home}/data`,
    variant === 1 ? `777 root:root ${inst}` : `750 dmdba:dinstall ${inst}`,
    variant === 1 ? `666 root:root ${inst}/dm.ini` : `600 dmdba:dinstall ${inst}/dm.ini`,
    variant === 1 ? `666 root:root ${inst}/dmarch.ini` : `640 dmdba:dinstall ${inst}/dmarch.ini`,
    variant === 1 ? `777 root:root ${inst}/audit` : `750 dmdba:dinstall ${inst}/audit`,
  ].join('\n');
  const listen = variant === 1 ? 'LISTEN 0 128 0.0.0.0:7237 0.0.0.0:*' : 'LISTEN 0 128 10.0.0.61:7236 0.0.0.0:*';
  const sshd = [
    variant === 1 ? 'PermitRootLogin yes' : 'PermitRootLogin no',
    'PasswordAuthentication yes',
    'PermitEmptyPasswords no',
    'PubkeyAuthentication yes',
  ].join('\n');
  const auditFiles =
    variant === 1
      ? ''
      : ['2020-01-01 1048576', '2024-06-30 2097152'].map((s) => `${s} ${inst}/audit/audit_${s.slice(0, 4)}.aud`).join('\n');
  return {
    proc,
    perms,
    listen,
    sshd,
    audit: auditFiles,
    plaintext:
      variant === 1
        ? `${home}/bin/start_db.sh:12:disql SYSDBA/Demo#Passw0rd!@10.0.0.62:7237 -e "select 1"`
        : '',
    history:
      variant === 1
        ? '37:disql SYSDBA/Demo#Passw0rd!@10.0.0.62:7237\n52:dmrman'
        : '', // 规范场景：**扫了但没命中**（grep 返回 1、输出为空）—— 这条分支曾被误判成「未取到」，必须有离线覆盖
  };
}
