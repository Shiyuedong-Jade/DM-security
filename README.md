# dsh-plugin-dm-security

达梦 DM8 数据库安全评估插件。执行 60 项只读检查，给出六态结论与等保 2.0 控制点对照，生成 HTML 报告。

## 目录

- [功能](#功能)
- [环境要求](#环境要求)
- [安装](#安装)
- [使用](#使用)
- [配置](#配置)
- [报告](#报告)
- [注意事项](#注意事项)
- [卸载](#卸载)
- [目录结构](#目录结构)
- [开发](#开发)
- [许可证](#许可证)

## 功能

- 60 项只读检查，分 13 个域：身份鉴别、认证方式与登录控制、口令策略、自主访问控制、职责分离、强制访问控制、安全审计、通信安全、存储加密、资源限制、访问路径、暴露面与代码安全、主机侧 OS/SSH
- 六态结论：严重 / 警告 / 提示 / 合规 / 不适用 / 未取到。不适用与未取到不计入统计，不给出评分
- 等保 2.0（GB/T 22239-2019）控制点对照，级别可选 2 / 3 / 4，默认三级。条款编号随级别改写，并给出条款级符合性（符合 / 部分符合 / 不符合 / 不适用 / 无法判定）
- 主机侧 7 项检查另需提供 SSH 账号：数据库进程运行账号、安装与数据目录权限、配置文件权限、实例监听绑定、明文口令痕迹、审计文件保留周期、宿主 sshd 基线
- 支持单实例与共享存储集群（DMDSC）逐节点评估，多节点时附节点间配置一致性核对
- 输出单文件 HTML 报告，零脚本、零外部依赖，带两级目录
- 库内 SQL 均为查询语句；主机侧只执行 7 条只读命令。两者都不修改数据库与主机配置

单实例与共享存储集群（两节点）都已完成真机验证。文档与报告示例里的地址、账号均做过替换，非真实环境。

## 环境要求

| 项 | 要求 |
|---|---|
| Node.js | ≥ 20 |
| Java | 8 及以上（JDK 或 JRE）。桥接器以源码方式运行，首次运行编译一次，结果缓存在工作目录 |
| 达梦 JDBC 驱动 | `DmJdbcDriver8.jar` 或 `DmJdbcDriver18.jar`，需自行提供，见[安装](#安装)第 2 步 |
| DeepSeek Harness | 0.1.x |
| plink | 仅主机侧检查需要，在 PATH 中即可，或用 `plinkPath` 指定 |

## 安装

### 1. 安装插件

```sh
dsh plugin --profile web add github:Shiyuedong-Jade/DM-security
```

从本地目录安装：

```sh
dsh plugin --profile web add file:/path/to/dsh-plugin-dm-security
```

`file:` 安装时绝对路径不能含空格：`dsh plugin` 会转发给 pnpm，参数在空格处断开。

### 2. 放置达梦 JDBC 驱动

驱动 jar 是达梦的商业组件，不随插件分发。把达梦安装目录下的
`dmdbms/drivers/jdbc/DmJdbcDriver8.jar` 复制到工作目录的 `drivers/` 下：

| 平台 | 路径 |
|---|---|
| Windows | `%USERPROFILE%\.dsh\dm-security\drivers\` |
| Linux | `~/.dsh/dm-security/drivers/` |

插件加载时会自动建好工作目录（`drivers/`、`java/`、`runtime/`）。工作目录可用插件配置 `home` 修改，见[配置](#配置)。

### 3. 重启

首次安装后重启 `dsh web`，并刷新已打开的页面。

## 使用

在会话里调用 `dm_security_assess`。目标、账号、口令可以在设置卡片里预先填好，也可以在每次调用时填。

工具有三个动作：

| action | 说明 |
|---|---|
| `assess` | 只读评估，在会话里给出文本结论 |
| `report` | 评估并落盘 HTML 报告 |
| `list` | 列出检查项目录，不连库 |

工具返回六态结论的分布、逐项结论和报告路径。报告为 HTML，文件名带对照级别与时间戳。

### 调用参数

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `action` | string | 必填 | `assess` / `report` / `list` |
| `driver` | string | `jdbc` | `jdbc` 连真实库；`demo` 使用内置样例数据，不连库 |
| `host` / `port` | string / integer | `127.0.0.1` / `5236` | 单实例目标 |
| `targets` | string | — | 多节点目标，`host:port` 以逗号或空格分隔。2 个及以上按集群逐节点评估 |
| `user` | string | `SYSDBA` | 数据库账号 |
| `password` | string | — | 数据库口令。会写入会话日志，建议改用设置卡片或凭据库 |
| `privs` | string | 自动判定 | 连接账号具备的权限层。账号是 `SYSDBA` 或持有 `DBA` 角色时按 SYSDBA 处理 |
| `level` | integer | `3` | 等保对照级别，2 / 3 / 4 |
| `sshUser` / `sshPassword` | string | — | 主机侧检查的 SSH 账号与口令。两者都填才会执行主机侧检查。多节点用逗号分隔且与 `targets` 同序（两节点的运维账号/口令未必相同），只给一个值时所有节点共用；这一项不按空格拆分（口令里可以有空格） |
| `sshHost` | string | 各目标自身主机 | SSH 目标主机，逗号分隔且与 `targets` 同序 |
| `sshPort` | integer | `22` | SSH 端口 |
| `sshHostKey` | string | — | 主机密钥指纹，逗号分隔且与 `targets` 同序。plink 在 `-batch` 模式下要求密钥已知 |
| `plinkPath` | string | `plink` | plink 可执行文件路径 |
| `osRetentionDays` | integer | `180` | 审计文件保留期要求（天），用于主机侧审计文件检查 |
| `outDir` | string | `<home>/dm-security-reports` | 报告目录 |
| `pwdPolicyMin` 等阈值 | integer | 见[配置](#配置) | 口令策略、锁定次数、会话占比等判定基线 |

取值优先级：本次调用参数 > 插件配置。

## 配置

写在 profile 的 `cordis.patch.yml` 中该插件那一行上，也可以在设置界面里修改：

```yaml
- insert:
    - id: dm-security
      name: 'dsh-plugin-dm-security'
      config:
        home: 'D:\dm-security-home'       # 工作目录，默认 ~/.dsh/dm-security
        host: '10.0.0.40'
        port: 5236
        user: 'SYSDBA'
        credentialRef: 'DM_SECURITY_PASSWORD'
        driver: 'jdbc'
        outDir: ''                         # 默认 <home>/dm-security-reports
        sshUser: 'dmdba'
        sshCredentialRef: 'DM_SECURITY_SSH_PASSWORD'
        osRetentionDays: 180
        pwdPolicyMin: 31
        pwdMinLen: 8
        pwdLifeMaxDays: 180
        failedLoginMax: 5
        maxSessionsWarnPct: 80
        sessionShareWarn: 50
```

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `home` | `~/.dsh/dm-security` | 工作目录，其下有 `drivers/`、`java/`、`runtime/` |
| `host` / `port` / `user` | `127.0.0.1` / `5236` / `SYSDBA` | 默认目标与账号 |
| `credentialRef` | — | 数据库口令的凭据名 |
| `driver` | `jdbc` | 默认驱动 |
| `outDir` | 空 | 报告目录，留空则用工作目录下的 `dm-security-reports` |
| `sshUser` / `sshCredentialRef` | — | 主机侧检查的 SSH 账号与凭据名 |
| `osRetentionDays` | `180` | 审计文件保留期要求（天） |
| `pwdPolicyMin` | `31` | `PWD_POLICY` 位掩码基线：禁同名 + 长度 + 大写 + 数字 + 标点 |
| `pwdMinLen` | `8` | 口令最小长度 |
| `pwdLifeMaxDays` | `180` | 口令有效期上限（天） |
| `failedLoginMax` | `5` | 登录失败锁定次数上限 |
| `maxSessionsWarnPct` | `80` | 实例会话上限使用率告警线（%） |
| `sessionShareWarn` | `50` | 单一来源会话占比告警线（%） |

### 口令的另外两种来源

环境变量（启动 dsh 前设置）：

```sh
export DM_SECURITY_PASSWORD='数据库口令'
export DM_SECURITY_SSH_PASSWORD='SSH口令'
```

或写入 `~/.dsh/.credentials.yaml` 的 `refs`，键名同上。

## 报告

HTML 单文件，零外部依赖，双击即可打开。

1. 封面：评估对象、数据库与实例、版本类型与内核版本号、采集账号、报告编号
2. 目录：两级，点击跳到对应章节，各章节标题右侧可跳回目录
3. 评估概况：采集账号与权限层判定、数据来源、OS 访问状态、评估标准、等保对照级别，以及版本与实例信息
4. 结论摘要：六态计数、分布条、每态的判定含义，以及最要紧的几件事
5. 分域明细：逐项给出结论、说明、整改建议、证据、所需权限与等保控制点
6. 等保 2.0 控制点对照：条款级符合性、判定依据、适用级别、最重结论与涉及的检查项
7. 加固项：不映射等保条款、只作加固参考的项
8. 未闭环清单：所有未取到的项与补齐办法
9. 附录：安全相关参数快照、评估方法与局限

DMDSC 多节点时，每节点各出一份报告，并在概况下增加节点间配置一致性一节。报告目录下不生成其他文件，JSON 只在 `tools/live-assess.mjs` 里另存，用于回填设计文档。

## 注意事项

- 所有库内 SQL 都是查询语句，不修改数据库任何配置。不试默认口令，不建审计策略，不采集口令散列。
- 主机侧只执行 `lib/ossh.js` 里 7 条只读命令（`ps`、`stat`、`ss`/`netstat`、`grep`、`find`）。命令只能由固定构造器产生，执行前再校验一次形态；路径参数逐字符校验，含分号或空格直接报错。未提供 SSH 账号时，主机侧 7 项判为「不适用」。
- 明文口令扫描的命中片段在采集层就掩码成 `用户/***@`，报告里不会出现口令原文。扫描范围是 `<DM_HOME>`（排除厂商自带目录）与运行账号的 `~/.bash_history`，只认 `disql`/`dmrman` 连接串形态。
- 普通版（标准版、企业版）不提供强制访问控制与四权分立，相关项判「不适用」，不计为不符合。
- 高等级专属条款在当前对照级别下判「不适用」，同时保留按更高等级口径给出的技术结论。级别切换后条款编号与要求范围都会变。
- 等保控制点编号与要求摘要为工作基线，正式判定以测评机构结论为准。
- 报告包含主机名、账号、目录路径与实测发现，不要提交到公开仓库或公共渠道。
- 口令在调用卡片中填写，插件不保存、不落盘；宿主的会话日志会记录调用参数，这一点插件无法避免。
- 报告默认输出到工作目录下的 `dm-security-reports`，不是 dsh 进程的启动目录。需要落到别处时传 `outDir`。
- 数据守护主备形态已在共享存储集群上验证过逐节点采集，但主备角色切换未实测。
- 以下环境未验证：安全版（`mac.*` 的六态路径）、DM9、Windows 上的达梦、ARM 架构（鲲鹏 / 飞腾）。
- `AUDIT_FILE_FULL_MODE` 的取值语义（写满后报错还是覆盖）未确认，报告只陈述取值不判方向。
- 开发时注意：宿主加载的是 profile 目录下的副本，改完代码要同步源码、安装目录与 profile 副本三处，再重启 dsh。
- Java 8 下首次运行会编译桥接器，产物在 `home/runtime/classes`；删除 `home/runtime/` 可清空，下次运行自动重建。

## 卸载

```sh
dsh plugin --profile web remove dsh-plugin-dm-security
```

再删除工作目录（其中包含驱动 jar）：

| 平台 | 命令 |
|---|---|
| Windows | `Remove-Item "$env:USERPROFILE\.dsh\dm-security" -Recurse -Force` |
| Linux | `rm -rf ~/.dsh/dm-security` |

## 目录结构

```
├── package.json          插件清单
├── cordis.patch.yml      作为 bundle 的插入清单
├── screenshots.json      报告截图清单（插件市场详情页用）
├── DESIGN.md             设计基线：判定口径、真机校准记录、待核实清单
├── SECURITY.md           只读边界、口令与凭据取舍、漏洞上报
├── CHANGELOG.md          变更记录
├── lib/
│   ├── index.js          插件入口：注册工具、解析参数与口令
│   ├── checks.js         60 项检查项定义（13 个域）
│   ├── compliance.js     等保控制点表与级别维度
│   ├── queries.js        只读查询定义，含降级链
│   ├── analyze.js        判定引擎：六态结论、级别闸门、条款级符合性
│   ├── ossh.js           主机侧只读采集：7 条命令白名单、plink 执行、掩码
│   ├── bridge.js         Node 与 Java 之间的只读桥
│   ├── report.js         HTML 与文本渲染
│   ├── dsc.js            多节点形态识别与节点间一致性核对
│   ├── util.js           列名容错、内置账号白名单
│   └── drivers/          jdbc 与 demo 两种采集驱动
├── assets/java/
│   └── DmQuery.java      JDBC 桥接器源码
├── assets/screenshot-*.png  报告截图，由 tools/shots.mjs 生成
├── .github/workflows/
│   ├── ci.yml            离线自检与演示报告生成
│   └── peer-range.yml    每周核对 peer 范围是否落后于 registry（需联网）
└── tools/                开发与自检脚本
```

## 开发

```sh
node tools/smoke.mjs                                      # 离线自检，214 项断言，不连库、不需要驱动
node tools/plugin-e2e.mjs                                 # 插件工具入口端到端，走生产代码路径
node tools/catalog.mjs                                    # 列出检查项目录，可加 --level 2|3|4
node tools/catalog.mjs demo-report                        # 用内置样例数据生成 HTML 报告
node tools/shots.mjs                                      # 重新生成 assets/ 下的报告截图（需要本机有 Edge / Chrome）
node tools/peer-range.mjs                                 # 核对 peer 范围是否还覆盖 registry 上已发布的版本（需联网）
node tools/live-assess.mjs 10.0.0.40:5236 --user appuser \
  --secret-file <口令文件>                                 # 连真实库评估一次，并打印每条查询的真实列名
node tools/plugin-e2e.mjs --targets "h1:7236,h2:7237" --user sysdba \
  --secret-file <口令文件> --ssh-user root \
  --ssh-secret-file <SSH口令文件> --ssh-host-key "k1,k2"    # 真机多节点，含主机侧检查
```

口令只从 `--secret-file` 或 `--secret-env` 指定的环境变量读，不进命令行。

改 `peerDependencies` 后请跑一次 `tools/peer-range.mjs`：它会拉 registry 上
`@deepseek-ai/*` 的全部已发布版本，逐个核对声明的范围有没有漏。预发布版本的放行规则很绕
（`*` 一个预发布都不匹配），手写范围漏掉新元组时不会有任何报错，只会让用户看到 peer 告警。

## 许可证

[MIT](LICENSE)
