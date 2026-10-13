/**
 * 达梦安全评估 —— 查询定义（**全部只读**）。
 *
 * 三条纪律（理由见 DESIGN §5）：
 *   1. **参数一律用 `SELECT *` 式全量取回**（`V$DM_INI` 只有几百行），
 *      绝不写 `WHERE PARA_NAME IN (...)` —— 参数名跨版本会变，写死会让整条语句报错、
 *      丢掉全部参数证据，而参数缺失本该表现为「该能力不适用」而不是「查询失败」。
 *   2. **用户/权限类不采集 `PASSWORD`**。首选显式安全列；降级到 `SELECT *` 时，
 *      分析层会丢掉 `PASSWORD` 列（见 analyze.js 的 redact）。
 *   3. **降级链只在报「无效的列名/表名」时生效**，且每一级都是「少取几列」，
 *      不是「换一条猜出来的语句」。
 *
 * 真机已验证过的语句（来源：02 组 dm8-inspect 在单实例 + DMDSC 上的实测）会标注 ✅。
 */

/** 形态识别：决定后续所有分支（含 na 判定）。 */
export const FORM_QUERIES = [
  {
    key: 'instance',
    sql:
      `SELECT INSTANCE_NAME, HOST_NAME, STATUS$, MODE$, SVR_VERSION, BUILD_VERSION FROM V$INSTANCE`,
    fallbacks: [`SELECT INSTANCE_NAME, HOST_NAME, STATUS$, MODE$, SVR_VERSION FROM V$INSTANCE`, `SELECT * FROM V$INSTANCE`],
  },
  {
    // ✅ 09 组真机验证（单实例 + DMDSC）
    key: 'database',
    sql: `SELECT NAME, DSC_NODES, ARCH_MODE, ROLE$, STATUS$ FROM V$DATABASE`,
    fallbacks: [`SELECT NAME, DSC_NODES, ARCH_MODE FROM V$DATABASE`, `SELECT * FROM V$DATABASE`],
  },
  { key: 'dwApply', sql: `SELECT COUNT(*) AS CNT FROM V$RAPPLY_SYS`, optional: true },
  { key: 'dwSend', sql: `SELECT COUNT(*) AS CNT FROM V$ARCH_SEND_INFO`, optional: true },
  // ✅ 09 组实测：V$DSC_EP_INFO 只有 6 列、没有地址列，故只能判「是不是集群」不能发现对端
  { key: 'dscEp', sql: `SELECT EP_NAME, EP_MODE, EP_STATUS FROM V$DSC_EP_INFO`, optional: true },
  {
    /**
     * ★ 版本类型（企业版 / 安全版 / 标准版）—— **权威判据**。
     *
     * 为什么不能靠「MAC 字典对象是否存在」来判安全版：2026-10-12 在 10.0.0.40 真机核对，
     * 该实例 `BUILD_TYPE=企业版`（普通版），但字典里**照样存在** `SYSMACLABELS` /
     * `VSYSMACLABELS` / `DB_POLICY_*` 角色 —— 用对象名做信号会把普通版误判成安全版，
     * 进而把「强制访问控制」判成「可用但未启用」（严重），而正确答案是「不适用」。
     *
     * 解码逻辑来自 02 组 `basic.build`，也就是用户在 disql 里手工执行的那一条：
     * ID_CODE 形如 `--03134284604-20260707-...`，取第一段非 `-` 子串的前两位：
     * 03=企业版 / 05=安全版 / 02=标准版。
     *
     * ★ 2026-10-12 实测结论（DM 8.1.5.60）：
     *   · **主语句 = 用户/02 组的原始形态**（最内层不带数据来源、靠外推解析 ID_CODE）。
     *     这样报告里的「版本号取值证据」与人工在 disql 中执行的语句**逐字一致**，可直接复核。
     *     实测该形态与显式形态结果完全相同（均为 8.1.5.60），且 `ID_CODE` 正确返回。
     *   · **降级 1 = 显式来源形态**（`FROM V$INSTANCE` + `ID_CODE` 透传）。02 组在其环境上
     *     遇到过原始形态报「无效的标识符」，所以留作跨版本兜底 —— 这正是降级链的用途。
     *   · 别名统一为 `INNER_VERSION`（用户脚本里写作 `INNER_VISION`，属拼写笔误）；
     *     分析层**同时容忍两个别名**，任一口径都能读。
     */
    key: 'buildType',
    sql:
      `SELECT ID_CODE, BUILD_TYPE, ` +
      `TO_NUMBER(SUBSTR(VER,1,2),'XX')||'.'||` +
      `TO_NUMBER(SUBSTR(VER,3,2),'XX')||'.'||` +
      `TO_NUMBER(SUBSTR(VER,5,2),'XX')||'.'||` +
      `TO_NUMBER(SUBSTR(VER,7,2),'XX') AS INNER_VERSION ` +
      `FROM (SELECT ` +
      `DECODE(SUBSTR(VER,1,2),'03','企业版','05','安全版','02','标准版','其他') AS BUILD_TYPE, ` +
      `RAWTOHEX(CAST(SUBSTR(VER,3) AS INT)) AS VER ` +
      `FROM (SELECT REGEXP_SUBSTR(ID_CODE,'[^-]+',1,1) AS VER))`,
    fallbacks: [
      // 降级 1：显式数据来源 + ID_CODE 透传（跨版本兜底）
      `SELECT ID_CODE, BUILD_TYPE, ` +
        `TO_NUMBER(SUBSTR(VER,1,2),'XX')||'.'||TO_NUMBER(SUBSTR(VER,3,2),'XX')||'.'||` +
        `TO_NUMBER(SUBSTR(VER,5,2),'XX')||'.'||TO_NUMBER(SUBSTR(VER,7,2),'XX') AS INNER_VERSION ` +
        `FROM (SELECT ID_CODE, ` +
        `DECODE(SUBSTR(VER,1,2),'03','企业版','05','安全版','02','标准版','其他') AS BUILD_TYPE, ` +
        `RAWTOHEX(CAST(SUBSTR(VER,3) AS INT)) AS VER ` +
        `FROM (SELECT ID_CODE, REGEXP_SUBSTR(ID_CODE,'[^-]+',1,1) AS VER FROM V$INSTANCE))`,
      `SELECT ID_CODE, DECODE(SUBSTR(REGEXP_SUBSTR(ID_CODE,'[^-]+',1,1),1,2),'03','企业版','05','安全版','02','标准版','其他') AS BUILD_TYPE FROM V$INSTANCE`,
      `SELECT ID_CODE FROM V$INSTANCE`,
    ],
    optional: true,
  },
  // ---- 以下三项对齐 02 组「基础信息」的取法（真机验证过），用于报告的「版本与实例信息」 ----
  {
    key: 'instanceRuntime',
    sql:
      `SELECT INSTANCE_NAME, TO_CHAR(START_TIME,'YYYY-MM-DD HH24:MI:SS') AS START_TIME, ` +
      `ROUND(SYSDATE - START_TIME, 2) AS RUN_DAYS, ROUND((SYSDATE - START_TIME) * 1440, 1) AS RUN_MINUTES ` +
      `FROM V$INSTANCE`,
    fallbacks: [`SELECT INSTANCE_NAME, TO_CHAR(START_TIME,'YYYY-MM-DD HH24:MI:SS') AS START_TIME FROM V$INSTANCE`, `SELECT * FROM V$INSTANCE`],
    optional: true,
  },
  {
    key: 'charset',
    sql:
      `SELECT SF_GET_UNICODE_FLAG() AS UNICODE_FLAG, SF_GET_CASE_SENSITIVE_FLAG() AS CASE_SENSITIVE, ` +
      `SF_GET_EXTENT_SIZE() AS EXTENT_SIZE, SF_GET_PAGE_SIZE() AS PAGE_SIZE_BYTES FROM DUAL`,
    optional: true,
  },
  {
    /**
     * 授权（License）有效期 —— 取法与 02 组 `basic.license` 一致。
     * 真机核对：`V$LICENSE.SERVER_VER` 原值可能就是 `X.X.x.x`，那是授权文件的**通配写法**、
     * 不是解析失败，所以在 SQL 侧翻译一次并保留原值，避免读者以为版本没取到。
     */
    key: 'license',
    sql:
      `SELECT SERIES_NO, SERVER_SERIES, SERVER_TYPE, ` +
      `CASE WHEN UPPER(SERVER_VER) LIKE '%X%' THEN '通配（授权文件为 ' || SERVER_VER || '）' ELSE SERVER_VER END AS SERVER_VER, ` +
      `TO_CHAR(EXPIRED_DATE,'YYYY-MM-DD') AS EXPIRED_DATE, AUTHORIZED_CUSTOMER, MAX_CPU_NUM, ` +
      `ROUND(EXPIRED_DATE - SYSDATE) AS DAYS_LEFT FROM V$LICENSE`,
    fallbacks: [`SELECT * FROM V$LICENSE`],
    optional: true,
  },
  {
    /**
     * ★ 表列加密的**实际覆盖**（2026-10-12 在 DM 8.1.5.60 的 DSC 节点上发现）。
     * 原设计把「列加密覆盖率」列为 P1，理由是「需要版本相关的加密元数据视图」——真机上这几个视图就是：
     * `ALL_ENCRYPTED_COLUMNS` / `DBA_ENCRYPTED_COLUMNS` / `USER_ENCRYPTED_COLUMNS`（各带一个同义词）。
     * 从此「哪些表列已加密」是**可判定**的，不再是能力陈述。
     */
    key: 'encColumns',
    sql: `SELECT COUNT(*) AS N FROM DBA_ENCRYPTED_COLUMNS`,
    fallbacks: [`SELECT COUNT(*) AS N FROM SYS.DBA_ENCRYPTED_COLUMNS`],
    optional: true,
  },
  {
    key: 'encColumnList',
    sql: `SELECT OWNER, TABLE_NAME, COLUMN_NAME FROM DBA_ENCRYPTED_COLUMNS ORDER BY OWNER, TABLE_NAME, COLUMN_NAME`,
    fallbacks: [`SELECT OWNER, TABLE_NAME, COLUMN_NAME FROM SYS.DBA_ENCRYPTED_COLUMNS`],
    optional: true,
  },
];

/**
 * 参数全量快照。
 *
 * 这是本插件**最重要的单一证据源**：审计开关、口令策略掩码、OS 认证、通信加密、
 * PRIV_FLAG（安全版信号）、GRANT_SCHEMA 全在这里。降级到只取名字+值，
 * 这样 `MIN_VALUE/MAX_VALUE/DESCRIPTION` 缺失时不至于丢掉整张参数表。
 */
export const PARAM_QUERY = {
  key: 'params',
  sql:
    `SELECT PARA_NAME, PARA_VALUE, FILE_VALUE, MIN_VALUE, MAX_VALUE, DEFAULT_VALUE, DESCRIPTION FROM V$DM_INI`,
  fallbacks: [
    `SELECT PARA_NAME, PARA_VALUE, FILE_VALUE FROM V$DM_INI`,
    `SELECT PARA_NAME, PARA_VALUE FROM V$DM_INI`,
  ],
};

/**
 * 账号清单。
 *
 * ⚠️ 首选列**显式排除 `PASSWORD`**：达梦的 `DBA_USERS` 带口令散列列，
 * `SELECT *` 会把它拉进结果文件与报告。降级到 `SELECT *` 是最后手段，
 * 分析层会按列名丢弃（analyze.js `redact`）。
 * ✅ `LOCK_DATE`/`EXPIRY_DATE`/`AUTHENTICATION_TYPE`/`CREATED` 四个列名由 02 组真机验证。
 */
export const USER_QUERIES = [
  {
    key: 'users',
    sql:
      `SELECT USERNAME, USER_ID, ACCOUNT_STATUS, DEFAULT_TABLESPACE, AUTHENTICATION_TYPE, ` +
      `TO_CHAR(LOCK_DATE,'YYYY-MM-DD HH24:MI:SS') AS LOCK_DATE, ` +
      `TO_CHAR(EXPIRY_DATE,'YYYY-MM-DD HH24:MI:SS') AS EXPIRY_DATE, ` +
      `TO_CHAR(CREATED,'YYYY-MM-DD HH24:MI:SS') AS CREATED_AT ` +
      `FROM DBA_USERS ORDER BY USERNAME`,
    fallbacks: [
      `SELECT USERNAME, USER_ID, ACCOUNT_STATUS, DEFAULT_TABLESPACE FROM DBA_USERS ORDER BY USERNAME`,
      `SELECT * FROM DBA_USERS`,
    ],
  },
  {
    // 账号级访问路径控制（IP 白/黑名单、登录时间段）。
    // ⚠️ **真机纠正（2026-10-12，10.0.0.40）**：这两个控制项**不在 DBA_USERS 上**，
    //    而在 `SYSUSERS`：`ALLOW_ADDR` / `NOT_ALLOW_ADDR` / `ALLOW_DT` / `NOT_ALLOW_DT`。
    //    达梦 8.1.3 企业版实测 `DBA_USERS` 里根本没有 ALLOW_IP/NOT_ALLOW_IP/ALLOW_DATETIME 列
    //    （文档里的 `ALTER USER ... ALLOW_IP` 语法写的是 SYSUSERS 的这两个字段）。
    //    首选走 SYSUSERS；DBA_USERS 那条保留为降级（万一别的版本放在那里）。
    key: 'userAccess',
    sql:
      `SELECT d.USERNAME, s.ALLOW_ADDR, s.NOT_ALLOW_ADDR, s.ALLOW_DT, s.NOT_ALLOW_DT ` +
      `FROM SYSUSERS s, DBA_USERS d WHERE s.ID = d.USER_ID ORDER BY d.USERNAME`,
    fallbacks: [
      `SELECT USERNAME, ALLOW_IP, NOT_ALLOW_IP, ALLOW_DATETIME FROM DBA_USERS ORDER BY USERNAME`,
      `SELECT USERNAME, ACCOUNT_STATUS FROM DBA_USERS ORDER BY USERNAME`,
    ],
    optional: true,
  },
];

/**
 * 口令策略与资源限制（逐账号）。
 *
 * ⚠️ **真机纠正（2026-10-12，10.0.0.40 实测 `SELECT * FROM SYSUSERS` 的 24 列）**：
 *    `SYSUSERS` 的真实列名是 `SESS_PER_USER`（不是 SESSION_PER_USER）、
 *    没有 `CPU_PER_SESSION` / `MEM_SPACE`（按用户的 CPU/内存限制不在 SYSUSERS，在 DBA_PROFILES），
 *    口令重用是 `REUSE_MAX` / `REUSE_TIME`，
 *    访问路径是 `ALLOW_ADDR` / `NOT_ALLOW_ADDR` / `ALLOW_DT` / `NOT_ALLOW_DT`，
 *    还有 `LAST_LOGIN_DTID` / `LAST_LOGIN_IP`（→ 账号休眠期检查因此变得可判定）。
 *
 * 首选语句已在真机验证通过；降级到 02 组验证过的 7 列形态（列缺失时对应检查项判「未取到」）。
 * **绝不查 `PASSWORD` / `OLD_PASSWORD` / `ENCRYPT_KEY`** —— SYSUSERS 这三列都是敏感列。
 */
export const PWD_QUERIES = [
  {
    key: 'pwdPolicy',
    sql:
      `SELECT d.USERNAME, s.PWD_POLICY, s.LIFE_TIME, s.FAILED_NUM, s.FAILED_ATTEMPS, s.LOCK_TIME, ` +
      `s.CONN_IDLE_TIME, s.SESS_PER_USER, s.REUSE_MAX, s.REUSE_TIME, s.ALLOW_ADDR, s.NOT_ALLOW_ADDR, ` +
      `s.ALLOW_DT, s.LAST_LOGIN_DTID, s.LAST_LOGIN_IP ` +
      `FROM SYSUSERS s, DBA_USERS d WHERE s.ID = d.USER_ID ORDER BY d.USERNAME`,
    fallbacks: [
      // ✅ 02 组真机验证形态（列缺失时的兜底；资源限制类检查项会因此判「未取到」）
      `SELECT d.USERNAME, s.PWD_POLICY, s.LIFE_TIME AS PWD_LIFE_DAYS, s.FAILED_NUM, s.FAILED_ATTEMPS, ` +
        `s.LOCK_TIME, s.CONN_IDLE_TIME, s.SESS_PER_USER FROM SYSUSERS s, DBA_USERS d WHERE s.ID = d.USER_ID ORDER BY d.USERNAME`,
      `SELECT d.USERNAME, s.PWD_POLICY, s.LIFE_TIME AS PWD_LIFE_DAYS, s.FAILED_NUM, s.FAILED_ATTEMPS, ` +
        `s.LOCK_TIME, s.CONN_IDLE_TIME FROM SYSUSERS s, DBA_USERS d WHERE s.ID = d.USER_ID ORDER BY d.USERNAME`,
    ],
    optional: true,
  },
];

/**
 * 权限类。
 * ✅ `DBA_ROLE_PRIVS` / `DBA_SYS_PRIVS` 的列名由 02 组真机验证。
 * ⚠️ `DBA_TAB_PRIVS` / `DBA_COL_PRIVS` 未经本工作区真机确认，故走显式列 → `SELECT *` 降级，且为 optional。
 */
export const PRIV_QUERIES = [
  { key: 'rolePrivs', sql: `SELECT GRANTEE, GRANTED_ROLE, ADMIN_OPTION FROM DBA_ROLE_PRIVS ORDER BY GRANTEE` },
  { key: 'sysPrivs', sql: `SELECT GRANTEE, PRIVILEGE, ADMIN_OPTION FROM DBA_SYS_PRIVS ORDER BY GRANTEE` },
  {
    key: 'tabPrivs',
    sql: `SELECT GRANTEE, OWNER, TABLE_NAME, PRIVILEGE, GRANTABLE FROM DBA_TAB_PRIVS`,
    fallbacks: [`SELECT * FROM DBA_TAB_PRIVS`],
    optional: true,
  },
  // ⚠️ 真机纠正：`DBA_ROLES` 的列是 `ROLE`（不是 NAME / ROLE_NAME）。
  //    原来只写 NAME/ROLE_NAME/GRANTED_ROLE 三个候选，真机上取不到任何角色名 → 清单为空。
  { key: 'roles', sql: `SELECT ROLE, PASSWORD_REQUIRED, AUTHENTICATION_TYPE FROM DBA_ROLES ORDER BY ROLE`, fallbacks: [`SELECT * FROM DBA_ROLES`], optional: true },
  // ✅ 真机验证：DBA_PROFILES 列为 PROFILE / RESOURCE_NAME / RESOURCE_TYPE / LIMIT，
  //    资源限制的「UNLIMITED」判定与 CPU/内存/口令重用检查都靠它。
  {
    key: 'profiles',
    sql: `SELECT PROFILE, RESOURCE_NAME, RESOURCE_TYPE, LIMIT FROM DBA_PROFILES ORDER BY PROFILE, RESOURCE_NAME`,
    fallbacks: [`SELECT * FROM DBA_PROFILES`],
    optional: true,
  },
];

/** 审计。`V$AUDITRECORDS` 在 SYSAUDITOR 名下；SYSDBA 可能也能读，两条都试。 */
export const AUDIT_QUERIES = [
  {
    key: 'auditRecords',
    sql: `SELECT COUNT(*) AS N FROM V$AUDITRECORDS`,
    fallbacks: [`SELECT COUNT(*) AS N FROM SYSAUDITOR.V$AUDITRECORDS`],
    optional: true,
  },
  // 能力发现：本版本到底有哪些审计相关字典对象？
  // 这是**通用发现**而不是「猜一个视图名」——查到什么就报什么，查不到说明确实没有。
  {
    key: 'auditDict',
    sql:
      `SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM DBA_OBJECTS ` +
      `WHERE (OWNER IN ('SYS','SYSAUDITOR') AND (UPPER(OBJECT_NAME) LIKE '%AUDIT%' OR UPPER(OBJECT_NAME) LIKE 'AUD$%')) ` +
      `ORDER BY OWNER, OBJECT_NAME`,
    fallbacks: [`SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM DBA_OBJECTS WHERE UPPER(OBJECT_NAME) LIKE '%AUDIT%' ORDER BY OWNER, OBJECT_NAME`],
    optional: true,
  },
];

/** 会话与来源（✅ 列名 USER_NAME/APPNAME/CLNT_IP/STATE 由 02 组真机验证）。 */
export const SESSION_QUERIES = [
  {
    key: 'sessions',
    sql:
      `SELECT USER_NAME, APPNAME, CLNT_IP, STATE, COUNT(*) AS CNT FROM V$SESSIONS ` +
      `GROUP BY USER_NAME, APPNAME, CLNT_IP, STATE ORDER BY CNT DESC`,
    fallbacks: [`SELECT USER_NAME, COUNT(*) AS CNT FROM V$SESSIONS GROUP BY USER_NAME ORDER BY CNT DESC`],
    optional: true,
  },
];

/** 作业与暴露面。`SYSJOB.SYSJOBS` 的列名（含带引号的 "ENABLE"）由 02 组真机验证。 */
export const EXPO_QUERIES = [
  {
    key: 'jobs',
    sql:
      `SELECT ID, NAME, "ENABLE" AS ENABLE_FLAG, USERNAME, TO_CHAR(CREATETIME,'YYYY-MM-DD HH24:MI:SS') AS CREATE_TIME ` +
      `FROM SYSJOB.SYSJOBS ORDER BY NAME`,
    fallbacks: [`SELECT ID, NAME FROM SYSJOB.SYSJOBS`],
    optional: true,
  },
  {
    // 危险包/过程的存在性。用 DBA_OBJECTS 查名字，**查不到 = 本版本没有**，不是猜视图。
    key: 'dangerousObjs',
    sql:
      `SELECT OWNER, OBJECT_NAME, OBJECT_TYPE, STATUS FROM DBA_OBJECTS WHERE OBJECT_NAME IN (` +
      `'UTL_FILE','DBMS_LOB','DBMS_SCHEDULER','DBMS_PIPE','DBMS_LOCK','DBMS_XMLGEN','DBMS_SQL','DBMS_JAVA','JAVA','DBMS_UTILITY','SP_CREATE_JOB','SP_FILE_SQL') ` +
      `ORDER BY OBJECT_NAME`,
    fallbacks: [
      `SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM DBA_OBJECTS WHERE OBJECT_NAME IN ('UTL_FILE','DBMS_LOB','DBMS_SCHEDULER','DBMS_JAVA','DBMS_UTILITY') ORDER BY OBJECT_NAME`,
    ],
    optional: true,
  },
  {
    key: 'synonyms',
    sql: `SELECT OWNER, SYNONYM_NAME, TABLE_OWNER, TABLE_NAME FROM DBA_SYNONYMS WHERE OWNER = 'PUBLIC' ORDER BY SYNONYM_NAME`,
    fallbacks: [`SELECT OWNER, SYNONYM_NAME FROM DBA_SYNONYMS WHERE OWNER = 'PUBLIC'`],
    optional: true,
  },
  {
    key: 'encObjs',
    sql:
      `SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM DBA_OBJECTS WHERE UPPER(OBJECT_NAME) LIKE '%ENCRYPT%' ` +
      `ORDER BY OWNER, OBJECT_NAME`,
    optional: true,
  },
];

/** 安全版能力发现（MAC 策略/标记对象）。**只做发现，不用于判定版本类型**（版本类型看 `buildType`）。 */
export const MAC_QUERIES = [
  {
    // ⚠️ 真机教训：原来写的是 `UPPER(OBJECT_NAME) LIKE '%_LABEL%'`，而 SQL LIKE 里 `_` 是
    //    **单字符通配符**，于是它实际等于 `%LABEL%`，把 `SYSMACLABELS` 也匹配进来了。
    //    现在改成明确的模式。
    key: 'macObjs',
    sql:
      `SELECT OWNER, OBJECT_NAME, OBJECT_TYPE FROM DBA_OBJECTS WHERE ` +
      `(UPPER(OBJECT_NAME) LIKE '%MACLABEL%' OR UPPER(OBJECT_NAME) LIKE '%MACPOLICY%' ` +
      `OR UPPER(OBJECT_NAME) LIKE '%COMPARTMENT%' OR UPPER(OBJECT_NAME) LIKE '%SECLABEL%' ` +
      `OR UPPER(OBJECT_NAME) LIKE '%PRIV_LABEL%' OR UPPER(OBJECT_NAME) LIKE '%POLICY_LABEL%') ` +
      `AND OWNER IN ('SYS','SYSSSO','SYSDBA') ORDER BY OWNER, OBJECT_NAME`,
    optional: true,
  },
];

/** 全部查询（顺序即执行顺序；桥会一次批量跑完）。 */
export const ALL_QUERIES = [
  ...FORM_QUERIES,
  PARAM_QUERY,
  ...USER_QUERIES,
  ...PWD_QUERIES,
  ...PRIV_QUERIES,
  ...AUDIT_QUERIES,
  ...SESSION_QUERIES,
  ...EXPO_QUERIES,
  ...MAC_QUERIES,
];

/**
 * 每个查询 key 的**用途说明**，供报告在展示证据时写清「这条 SQL 是为了查什么」。
 * 键缺失时报告只展示 SQL 原文，不留空白。
 */
export const QUERY_PURPOSE = {
  instance: '实例与版本（形态识别、补丁基线）',
  database: '库名与集群形态（单实例 / DMDSC 节点数）',
  dwApply: '数据守护备库应用信息（判断是否主备）',
  dwSend: '数据守护归档发送信息（判断是否主备）',
  dscEp: '共享存储集群节点信息',
  buildType: '版本类型（企业版/安全版/标准版）、四位内核版本号与 ID_CODE —— 安全能力的权威判据',
  instanceRuntime: '实例名、启动时间与运行时长',
  charset: '字符集 / 大小写敏感 / 簇大小 / 页大小（建库时确定、事后不可改）',
  license: '授权（License）有效期与剩余天数',
  params: '安全相关参数全量快照（审计/口令/认证/加密/PRIV_FLAG）',
  users: '账号状态与认证方式（不含口令散列）',
  userAccess: '账号级 IP 白黑名单与登录时间段',
  pwdPolicy: '逐账号口令策略与资源限制',
  rolePrivs: '角色授予关系（含转授权）',
  sysPrivs: '系统权限授予关系',
  tabPrivs: '对象权限授予关系',
  roles: '角色清单（区分内置与自定义）',
  profiles: 'PROFILE 资源限制配置',
  auditRecords: '审计记录行数（判断审计是否真在产生记录）',
  auditDict: '审计相关字典对象发现',
  sessions: '当前连接来源分布',
  jobs: '作业（定时任务）清单',
  dangerousObjs: '危险包/过程存在性',
  synonyms: 'PUBLIC 同义词',
  encObjs: '加密相关对象发现',
  encColumns: '表列加密的实际覆盖（加密列数量）',
  encColumnList: '已加密的表列清单',
  macObjs: '强制访问控制策略/标记对象发现',
};
