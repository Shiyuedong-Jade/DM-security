# 达梦数据库安全评估插件（`dsh-plugin-dm-security`）

> 把「这台 DM8 的安全配置到底合不合规、风险在哪」变成一份**只读、带证据、可追溯**的结论。
> 13 个域 / 60 项检查（53 项库内 + **7 项主机侧 OS/SSH**）/ 六态结论 / 等保 2.0 控制点对照（**二 / 三 / 四级可选，默认三级**，含要求摘要）/ 单文件 HTML 报告。

配套文档：`DESIGN.md`（设计基线、判定口径、待核实清单）。

---

## 1. 它回答什么，不回答什么

| 回答 | 不回答 |
|---|---|
| 账号、口令策略、权限、审计、加密、资源限制是否符合基线 | 不回答「库跑得快不快」——那是 `dm8-inspect` 巡检的领域 |
| 哪些配置是**严重**风险、证据是哪条 SQL、怎么改 | 不替你改：**修复 SQL 只给不执行** |
| 每个结论映射到哪个等保控制点 | 不下「有没有已知漏洞」的结论（P3，无内置漏洞库） |
| 哪些项**不适用**（普通版没有该能力 / 高等级专属条款在你那一级本就不要求）、哪些项**没取到**（要什么才能取到） | 不试默认口令、不建审计策略试探、不改资源限制 |

### 硬边界（写死在实现里，不是配置项）

1. **只读**：JDBC 桥只放行 `SELECT` / `WITH`，其余一律拒绝并计入 `rejected`。
2. **不试口令**：默认口令是否已改无法自动判定（达梦字典不提供「口令上次修改时间」），报告给**人工核对清单**，而不是靠试登录来验证。
3. **不采集口令散列**：`DBA_USERS` 的首选列不含 `PASSWORD`；万一降级到 `SELECT *`，分析层会按列名抹掉（自检有负向用例）。
4. **不适用 ≠ 不合规**：普通版（标准版/企业版）不提供强制访问控制与四权分立，判「不适用」，不计入结论统计。

---

## 2. 判定口径（六态）

| 态 | 含义 | 是否计分 |
|---|---|---|
| 严重 | 直接违反硬性要求或造成实质暴露 | 计入 |
| 警告 | 偏离基线、有风险但可解释 | 计入（记半分） |
| 合规 | 满足基线 | 计入（满分） |
| 提示 | 仅陈述事实/能力发现 | 不计入 |
| 不适用 | 本版本/本形态不提供该能力 | **剔除** |
| 未取到 | 权限不足 / 字典不存在 / 需 OS 侧数据 | **剔除**，单列「未闭环清单」并给补齐办法 |

**不给出评分**（2026-10-12 取消）：加权分会把「审计未开启（硬性不符合）」与「PROFILE 没设 CPU 上限（加固建议）」
压成同一个数字，读者容易只盯分数不看具体项；等保测评本身也是逐条判「符合/部分符合/不符合/不适用」而非打分。
现在只输出**结论分布**（六态计数）+ 已判定项数 + 逐项结论，排优先级靠「最要紧的几件事」。

---

## 3. 13 个域

| 域 | 项数 | 主要内容 |
|---|---|---|
| 身份鉴别 | 4 | 管理员账号状态、业务账号锁定/过期、OS 认证账号、内置账号清单 |
| 认证方式与登录控制 | 5 | 本地/远程 OS 认证、外部认证痕迹、账号级 IP 白黑名单、登录时间段 |
| 口令策略 | 8 | `PWD_POLICY` 位掩码、最小长度、有效期、失败锁定与锁定时长、重用限制、空闲超时 |
| 自主访问控制 | 9 | DBA 持有者与转授权、ANY 类权限、GRANT ANY、账号管理权限、PUBLIC 权限、自定义角色、模式级授权 |
| 职责分离 | 3 | `PRIV_FLAG` 三权/四权、各管理员可用性、管理员权限交叉 |
| 强制访问控制 | 2 | 安全版能力判定、MAC 策略与标记对象（仅安全版） |
| 安全审计 | 6 | 审计开关、实时审计、**审计是否真在产生记录**、审计文件大小与写满策略、SQL 日志 |
| 通信安全 | 2 | 通信加密开关、加密相关参数清单 |
| 存储加密 | 1 | 存储加密能力与启用迹象 |
| 资源限制 | 6 | PROFILE、并发会话数、CPU、内存、实例会话上限、管理员资源限制 |
| 访问路径 | 1 | 当前连接来源分布（IP 已脱敏） |
| 暴露面与代码安全 | 5 | 危险包 EXECUTE 授权、作业清单、PUBLIC 同义词、版本与补丁、默认口令人工核对 |
| **主机侧（OS / SSH）** | **7** | 需配 SSH：进程运行账号、安装/数据/审计目录权限、`dm.ini` 等配置权限、监听绑定、明文口令痕迹、审计文件保留、宿主 sshd 基线 |

> 主机侧那 7 项**只在给了 `sshUser` + `sshPassword` 时**才做；没给就整域判「不适用」并说明怎么开，
> 插件退回纯 JDBC 只读。命令白名单、掩码与三态降级见 `DESIGN.md` §5.6。

---

## 4. 安装

三种方式，按需选：

```powershell
# ① 从 GitHub 安装（推荐；仓库根就是插件包）
dsh plugin --profile web add github:Shiyuedong-Jade/dsh-plugin-dm-security

# ② 本地目录安装（开发时用）—— 注意 `dsh plugin` 转发给 pnpm 时会在**空格处断开**，
#    所以先把包复制到无空格路径
Copy-Item -Recurse 'D:\Agent workarea\10-达梦安全评估插件\dsh-plugin-dm-security' D:\dsh-plugins\   # 排除 node_modules
dsh plugin --profile web add file:D:\dsh-plugins\dsh-plugin-dm-security
#    路径没有空格时，也可以直接 file: 指向 clone 出来的目录
```

安装后会看到：

```json
// ~/.dsh/profiles/web/package.json
"dependencies": { "dsh-plugin-dm-security": "file:D:/dsh-plugins/dsh-plugin-dm-security" },
"dsh": { "profile": { "bundles": [ ..., "dsh-plugin-dm-security" ], "patchReload": "live" } }
```

> **生效时机**：`bundles` 是插件加载清单，**改完要重启 DSH 宿主**才会注册出
> `dm_security_assess` 工具（`patchReload: live` 只对 `cordis.patch.yml` 生效）。
> 重启前可以先自证安装是好的 —— 在 profile 目录执行下面这条，应打印出工具名与六态分布：
>
> ```powershell
> cd ~\.dsh\profiles\web
> node --input-type=module -e "const p=await import('dsh-plugin-dm-security');let t=null;p.apply({tools:{register:x=>t=x}});const v=await t.execute({action:'assess',driver:'demo'});console.log(t.name);console.log(v.text.split('\n').find(l=>l.includes('结论分布')))"
> ```
>
> 本机已实测通过（工具名 `dm_security_assess` + 六态分布行）。注意**没有** `score`/`grade` 字段 —— 评分已取消。

还需要几样东西（都不随插件分发）：

| 依赖 | 放哪里 |
|---|---|
| 达梦 JDBC 驱动 `DmJdbcDriver8.jar` | `<home>/drivers/`，`<home>` 默认 `~/.dsh/dm-security` —— **达梦商业组件，本仓库不包含、不得再分发**，请从你自己的达梦安装介质复制 |
| JDK（要 `javac`，不只是 JRE） | PATH 或 `JAVA_HOME`（桥以 `.java` 源码分发，首次运行时编译） |
| `plink`（主机侧检查用，可选） | PATH，或调用时给 `plinkPath` |
| 达梦 JDBC 驱动 | `<home>/drivers/DmJdbcDriver8.jar`，`<home>` 默认 `~/.dsh/dm-security`（已就位） |
| JDK（要 `javac`，不只是 JRE） | PATH 或 `JAVA_HOME` |

调用时直接给目标即可（和 `dm8-inspect` 一样，不必写 profile 配置）。
**口令的常规用法就是每次调用时在卡片里现填** —— 不保存、不落盘、不写进任何配置文件：

```yaml
dm_security_assess action=report host=10.0.0.40 port=5236 user=appuser password=***
```

| 口令来源 | 怎么做 | 特点 |
|---|---|---|
| **调用卡片现填**（默认、推荐） | 每次调用时填 `password` | 插件不保存、不落盘、不写进报告；唯一痕迹是**宿主的会话日志** |
| 凭据库（可选） | 插件配置里填 `credentialRef`，调用时不再填口令 | 口令不进会话日志；需要先把口令存进凭据库 |

想省掉每次填 host/port（**不要**把口令写进配置，那样就落盘了），可在
`~/.dsh/profiles/web/cordis.patch.yml` 里按 id 覆盖连接参数：

```yaml
- insert:
    - id: dm-security
      name: 'dsh-plugin-dm-security'
      config:
        host: 10.0.0.40
        port: 5236
        user: appuser
        # password 不写在这里 —— 每次在调用卡片里填
        # credentialRef: dm_security_PASSWORD   # 只有在用凭据库时才需要这一行
```

---

## 5. 使用

| action | 说明 |
|---|---|
| `assess` | 只读评估，在会话里给出文本结论 |
| `report` | 评估并落盘 HTML 报告（默认 `<home>/dm-security-reports`） |
| `list` | 只列检查项目录，**不连库** |

```
# 看评估口径（不连库）
dm_security_assess action=list

# 真实评估 + 出报告
dm_security_assess action=report host=10.0.0.40 port=5236

# DMDSC / 数据守护：逐节点评估 + **节点间配置一致性核对**
#（达梦的 V$DSC_EP_INFO 不含地址列，对端必须你来给）
dm_security_assess action=report targets="10.0.0.61:7236,10.0.0.62:7237"

# 没有环境也能看报告形态与判定分支
dm_security_assess action=report driver=demo

# 等保对照级别：level=2 / 3 / 4（默认 3）
#   级别决定 ① 条款编号（二级 7.1.4.x / 三级 8.1.4.x / 四级 9.1.4.x）
#            ② 要求范围 —— 高等级专属条款在本级判「不适用」而不是「不符合」，
#               但技术结论、证据与整改建议仍保留（升级定级时可直接复用）
dm_security_assess action=report level=2 host=10.0.0.61 port=7236
dm_security_assess action=list  level=2          # 目录里直接标出「第 N 级起要求，本级不适用」

# 主机侧（OS/SSH）7 项：给 sshUser + sshPassword 才做，不给就整域判「不适用」
#   逐节点主机密钥用逗号列表（DMDSC 两节点指纹不同，实测 SHA256:Zk6v3… / SHA256:PcGIK…）
dm_security_assess action=report targets="10.0.0.61:7236,10.0.0.62:7237" \
  sshUser=root sshPassword=*** \
  sshHostKey="SHA256:Zk6v3f6+7XDYylw990on1y3TyZNESoilDW12zOJUR3M,SHA256:PcGIKWi+0ntDBhopYYExQvbSPetABpjq509cPuajiyY"
```

**主机侧的安全边界**（写死在 `lib/ossh.js` 里）：只执行 7 条**只读**命令（`ps` / `stat` / `ss|netstat` /
`grep` / `find`），没有写动词、没有重定向；命令只能由构造器产生、执行前再验一遍形态；路径参数逐字符校验
（注入直接抛错）；明文口令扫描的命中片段**在采集层就掩码**成 `用户/***@`。详见 `DESIGN.md` §5.6。

**为什么默认三级**：等保定级定的是**信息系统**、不是数据库；三级在本插件用到的范围内基本覆盖二级 ——
按三级做不会漏检，二级客户只是多出几条按级别降级为「不适用」的项。反之按二级做，三级客户会整条漏掉
双因素、安全标记、审计进程保护、管理终端限制、漏洞修补、热冗余这一批。四级不适合当默认：其增量
（强制访问控制、四权分立）只有达梦安全版才有对应能力。详见 `DESIGN.md` §2.5。

**级别差异导致的「不适用」长什么样**：报告里带 `第 N 级起要求` 蓝色标记，等保对照表有「适用级别」列、
本级不适用的行整行压淡；结论摘要里单列一条「级别筛选」。它**不等于**「已合规」——技术结论就写在该项的
`items` 里（`技术结论（按第 3 级口径）：警告 —— …`）。

阈值可覆盖（都是业务决策，不是写死的常量）：`pwdPolicyMin`、`pwdMinLen`、`pwdLifeMaxDays`、`failedLoginMax`、`maxSessionsWarnPct`、`sessionShareWarn`、`dormantDays`。

**权限层自动判定**（`privs` 参数一般不用填）：连接账号是 `SYSDBA`、或该账号持有 `DBA` 角色时按 SYSDBA 判定；
否则所有需要 SYSDBA 的检查项判「未取到」并说明原因 —— **不会拿没权限的数据下结论**。
真机上用 `APPUSER`（持有 DBA 角色）连接即属前者，报告头部会写明判定依据。

### 命令行（不需要 DSH、不连库）

```bash
node tools/smoke.mjs                   # 离线自检（204 项断言）
node tools/plugin-e2e.mjs              # 插件工具入口端到端（demo/list，离线）
node tools/catalog.mjs                 # 列出 60 项检查项目录
node tools/catalog.mjs demo-report     # 用内置演示数据生成 HTML 报告

# 真机（需要口令文件；不会用错误口令试探，也不会把口令写进日志）
node tools/plugin-e2e.mjs 10.0.0.40:5236 --user appuser --secret-file <口令文件>
node tools/live-assess.mjs 10.0.0.40:5236 --user appuser --secret-file <口令文件>
```

---

## 6. 报告形态

单文件 HTML，**零外部依赖**（无 CDN、无外链、**无脚本**），拷到任何机器双击可看：

**目录（TOC）**：封面之后就是目录，**两层**（章节 + 各分域 + 等保各章条，共 35 个条目），点击即跳转到对应章节；
跳转有平滑滚动与目标高亮，每个章节标题右侧有「↑ 目录」回跳。全部用 CSS 锚点实现，没有脚本。

1. 头部：实例 / 版本 / 部署形态 / 安全版能力 / 职责分离形态
2. 结论分布：六态计数 + 每态的判定含义（**不给出评分**）；评估概况表含**采集账号与权限层判定依据**
3. **最要紧的几件事**：按严重→警告排序，带修复建议
4. 分域明细：每项给 结论 / 说明 / 修复建议 / 证据 SQL 与用途 / 所需权限 / 等保控制点 / 可展开的证据表
   - **多项内容一律渲染成列表**（一项一行），不堆成逗号串；`message` 只留一句结论
     （约定见 `DESIGN.md` §2.4，自检里有关门断言防止退回一坨文字）
5. 等保 2.0 控制点映射矩阵（标题与编号随 `level` 变化；含**适用级别**列与级别口径说明）
   - **条款级「符合性」**：把每条的检查项六态归纳成 **符合 / 部分符合 / 不符合 / 不适用 / 无法判定**，
     给出判定依据，并在「涉及检查项」里标出每个单项自己的结论；上方有各符合性的条数看板与判法说明。
     判法保守：**「合规 + 未取到」判部分符合、只有「提示」判无法判定** —— 没证据就不说符合（见 `DESIGN.md` §2.7）。
6. **未闭环清单**：所有「未取到」+ 补齐办法
7. 附录：安全相关参数快照
8. 免责与边界

---

## 7. 开发

```
dsh-plugin-dm-security/
├─ lib/
│  ├─ index.js        DSH 插件入口与工具注册
│  ├─ checks.js       60 项检查项（与 DESIGN.md §4 表格一一对应；等保编号按三级书写）
│  ├─ compliance.js   等保控制点表 + 级别维度（minLevel / parseControl(id, level) / levelBasis）
│  ├─ ossh.js        ★ 主机侧只读采集：7 条命令白名单 + plink 执行 + 掩码 + 三态降级（P2）
│  ├─ queries.js      只读查询定义（含降级链）
│  ├─ analyze.js      判定引擎：六态、级别闸门、等保映射矩阵、口令散列丢弃
│  ├─ report.js       HTML / 文本渲染
│  ├─ bridge.js       Node ↔ Java 只读桥
│  ├─ util.js         列名容错、内置账号白名单
│  └─ drivers/        jdbc（真实库）/ demo（内置样例）
├─ assets/java/DmQuery.java   只读桥（复用 09 组已真机验证的实现）
└─ tools/
   ├─ smoke.mjs        离线自检（137 项断言，不连库）
   ├─ plugin-e2e.mjs   插件工具入口端到端：走**生产代码路径**（apply + execute），支持 --level
   ├─ catalog.mjs      离线目录 / 演示报告（--level 2|3|4）
   └─ live-assess.mjs  真机验证（连真实库）：打印每条查询的真实列名、判定结果，
                       以及 DESIGN §8「待核实清单」的自动对账，并落盘 HTML + findings JSON
```

**为什么 `plugin-e2e.mjs` 和 `live-assess.mjs` 要分开**：后者是验证脚本，直接调 `collect`/`runChecks`；
用户实际用的是插件注册出来的工具，中间还隔着参数编译、口令解析、权限层判定、报告落盘、输出 schema
一整套胶水代码 —— 不测就等于没验过。`plugin-e2e.mjs` 测的正是那一段。

两个脚本的口令来源都是 `--secret-file <路径>`（推荐，不进命令行）或 `--secret-env <变量名>`；
**不会用错误口令试探**（那会累加失败登录次数、可能锁掉账号），写文件前自查「输出里是否出现口令」。

自检 `node tools/smoke.mjs` 断言（对应 DESIGN §9）：

- `checks.js` 的 ID 集合与 `DESIGN.md` §4 表格**完全一致**（防文档与代码漂移）；
- 所有 SQL 只以 `SELECT`/`WITH` 开头、无写关键字；Java 桥只有 `SELECT`/`WITH` 白名单；
- `redact()` 与 `rowsToObjects()` 都真的抹掉口令散列（负向用例）；
- `demo` 模式六态结论全部出现，17 个判定锚点命中，`na`/`unknown` 均有非空原因；
- 报告不含 `<script>`、无外链、不出现口令散列明文。

> **本地开发提示**：仓库里的 `node_modules/` 是指向 `09` 组插件 `node_modules` 的**目录联接**，
> 只为让 `node tools/smoke.mjs` 能解析 `@deepseek-ai/dsh-tools`；正式安装时由 `dsh plugin` 走 pnpm 装 peerDependencies。

---

## 8. 已知边界与真机验证状态

### 8.1 真机验证（2026-10-12，`10.0.0.40`）

环境：DM8 **企业版**，内核 `8.1.5.60`（由 `ID_CODE` 解出），单实例，用库内采集账号 `APPUSER`（**非 SYSDBA**）采集。
`tools/live-assess.mjs` 跑通全流程，当时 53 项里：**严重 1 / 警告 8 / 提示 22 / 合规 17 / 不适用 4 / 未取到 1**（已判定 26 项；不给出评分）。

这一轮**纠正了 9 处按文档写就会错的口径**，详见 `DESIGN.md` §4.1。最要紧的三条：

1. **版本类型只能看 `V$INSTANCE.ID_CODE` 解码出的 `BUILD_TYPE`** —— 该实例是企业版，但字典里照样有
   `SYSMACLABELS`/`DB_POLICY_*`，用「MAC 对象存在」判安全版会得出完全相反的结论。
2. **跨版本降级链的触发条件要认达梦的报错措辞** —— 达梦对「列不存在」报的是
   `无法解析的成员访问表达式[...]`，不认这个措辞，整个降级设计在真机上一次都不会触发。
3. **强权限挂在角色上，不挂在账号上** —— `GRANTEE` 出现 `DBA`/`DB_AUDIT_ADMIN`/`DB_POLICY_ADMIN` 是
   角色设计如此；不区分「授予角色」与「授予账号」，真机上会直接产出 3 条严重误报。

### 8.2 仍然未闭环

- **DMDSC 已真机验证**（`10.0.0.61:7236` + `10.0.0.62:7237`，2026-10-12）：两节点各出一份报告、
  节点覆盖度与**节点间一致性核对**均正常；用 `PORT_NUM`（7236 / 7237）确认 **`V$DM_INI` 是按节点返回的**，
  差异核对前提成立；本次两节点**一致 17 项、漂移 0 项**。详见 `DESIGN.md` §5.5。
- **等保对照级别已在真机验证**（2026-10-12，DSC `10.0.0.61/62`）：`level=2` 时 6 个三级专属检查项
  （`auth.ip_whitelist`、`auth.login_window`、`net.session_sources`、`mac.edition`、`mac.policy_objects`、
  `expo.version_patch`）正确降级为「不适用」，其中的 4 项原本是警告/提示 —— 级别差异**不再算作不符合**，
  但技术结论仍逐项保留；报告落盘为 `…-L2-….html` 与 `…-L3-….html` 两套。详见 `DESIGN.md` §2.5。
- **主机侧（P2）已在真机验证**（2026-10-13，DSC `10.0.0.61/62`，`--ssh-user root` + 逐节点主机密钥）：
  7 项全部判到底 —— `os.run_user` **合规**（dmdba 运行，非 root）；`os.dm_home_perms` 警告（`data`/`DSC01`/`DSC01_conf` 均 755）；
  `os.config_file_perms` 警告（`dm.ini` 644）；`os.listen_binding` 警告（监听 `*`，所有网卡）；
  `os.plaintext_credential` **警告 5 处真命中**（`~/.bash_history` 里手打的 `disql appuser/***@…`，片段已掩码）；
  `os.audit_retention` 警告（审计目录不存在，与库内 `ENABLE_AUDIT=0` 相互印证）；`os.sshd_baseline` 警告（`PermitRootLogin yes`）。
  生产代码路径 `plugin-e2e … --ssh-user … --ssh-secret-file …` **89/89 通过**，两份报告零口令泄漏。详见 `DESIGN.md` §5.6。
- 未验：安全版专属能力（`mac.*` 的六态路径，手边无安全版介质）。DMASM 存储形态、备份/归档取证与
  表列加密覆盖率（P1，`DBA_ENCRYPTED_COLUMNS`）已在真机确认，见 `DESIGN.md` §5.5。
- `AUDIT_FILE_FULL_MODE` 的取值语义（写满后报错还是覆盖）未确认，报告**只陈述取值不判方向**。
- `expo.dangerous_exec`：PUBLIC 可执行 6 个系统包，但**无法区分是安装默认还是后加**（插件看不到授权历史），
  报告文案已明确标注该不确定性并给出「与全新安装对比」的验证路径。
- 审计记录（`audit.records_exist`）需要 **SYSAUDITOR** 账号才读得到 —— 用非 SYSDBA 账号采集时该项诚实判「未取到」。
- **明文口令扫描的范围与形态**：只扫 `<DM_HOME>`（排除 `tool/`、`drivers/`、`client_ssl/` 等厂商自带目录）
  与运行账号的 `~/.bash_history`，只认 `disql`/`dmrman` 连接串形态 —— 应用配置文件里的凭据需人工核对。
- 补丁/漏洞基线属 P3，需要维护漏洞库。

### 8.3 其余已知边界

- **等保控制点编号**是工作基线，测评前需与测评机构确认；级别归属（哪条是二级、哪条三级起）已核对并做成 `level` 参数，但四级增量未逐条展开。
- 「不适用」「未取到」在真机上是常态（该 DSC 环境三级对照下分别 5 项与 1 项；切到二级对照时，另有 4 项因子级差异转为不适用），不是插件失败。

详见 `DESIGN.md` §8 与 §10。
