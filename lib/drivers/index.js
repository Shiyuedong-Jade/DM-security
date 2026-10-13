/**
 * 采集驱动选择。
 *
 *   jdbc  连真实达梦库（默认）
 *   demo  内置样例数据，不连库（自检、演示、无环境时验证判定分支）
 *
 * 两者返回**完全相同的形状**（`{ [key]: {columns, rows, error, sqlUsed} }`），
 * 上层的判定逻辑对数据来源无感知。
 *
 * ★ 主机侧（P2）是**另一条通道**：走 SSH 而不是 JDBC，所以单独一个 `collectOs()`，
 *   返回的不是「查询结果」而是「结构化事实 + 原始回显」（见 `ossh.js` 的 `buildOsFacts`）。
 *   没配 SSH 时它返回 `null`（上层据此判「本次未启用 OS 访问」），而不是假造一份空事实。
 */

import { runQueries } from '../bridge.js';
import { runDemoQueries, demoOsOutputs } from './demo.js';
import { buildOsFacts, judgeAuditRetention, deriveDmHome, deriveHomeDir, probeOs } from '../ossh.js';

export const DRIVERS = ['jdbc', 'demo'];

/**
 * 演示驱动的场景选择（只对 driver=demo 生效）：
 *   · host 含 `dsc`    → 造一套 **DMDSC 双节点**样例（`DSC_NODES=2` + 两个节点名）
 *   · host 以 `2` 结尾 → 造**第二节点**样例（审计已开、本地 OS 认证已关、主机名不同；
 *                        主机侧也换成「故意做坏」的那套：root 运行、目录 777、监听全网卡、明文口令）
 * 这样「多节点采集 → 逐节点报告 → **节点间一致性核对**」这条 DSC 专有路径，
 * 无需真实集群就能离线回归。
 */
function demoOptions(host) {
  const h = String(host ?? '').replace(/:\d+$/, '');
  return { dsc: /dsc/i.test(h), variant: /2$/.test(h) ? 1 : 0 };
}

export async function collect(conn, queries) {
  if (conn.driver === 'demo') return runDemoQueries(queries, demoOptions(conn.host));
  return runQueries(conn, queries);
}

/**
 * 主机侧采集（P2）。
 *   · demo：用内置样例（两套场景，覆盖「合规」与「严重」两条判定路径）
 *   · jdbc：配了 SSH 才做；没配返回 `null`
 */
export function collectOs(conn, { ssh = null, dbPort = null, retentionDays = 180 } = {}) {
  if (conn.driver === 'demo') {
    const { variant } = demoOptions(conn.host);
    const sshLike = { host: conn.host, port: 22, user: variant === 1 ? 'root' : 'dmdba' };
    const facts = buildOsFacts({ outputs: demoOsOutputs({ variant }), ssh: sshLike });
    facts.dbPort = dbPort;
    facts.retentionDays = retentionDays;
    facts.retention = judgeAuditRetention(facts.auditFiles, retentionDays);
    facts.auditDir = facts.paths.find((p) => /\/audit$/.test(p)) ?? null;
    facts.homeDir = deriveHomeDir(facts.primaryProcess, sshLike.user);
    facts.dmHome = deriveDmHome(facts.primaryProcess);
    /**
     * 演示场景也给出**退出码**：`grep` 找不到命中时返回 1（正常），这与「命令没跑」在输出上一样，
     * 不给退出码的话「扫了但干净」这条分支在离线自检里跑不到（真机清理后才暴露，见 DESIGN §5.6）。
     */
    facts.exit = { proc: 0, perms: 0, listen: 0, sshd: 0, audit: variant === 1 ? 0 : 1, plaintext: variant === 1 ? 0 : 1, history: variant === 1 ? 0 : 1 };
    return {
      state: 'ok',
      detail: `演示数据：主机侧${variant === 1 ? '（节点 2 · 故意做坏）' : '（规范配置）'}`,
      facts,
      commands: [],
      trouble: null,
    };
  }
  if (!ssh) return null;
  return probeOs({ ssh, dbPort, retentionDays });
}
