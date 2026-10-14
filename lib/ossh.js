/**
 * OS 访问层（P2）—— 在数据库主机上执行**极少数只读命令**，用于补齐「库内看不到」的那半壁。
 *
 * ## 这一层改变了插件的信任边界，所以边界写死在代码里，不靠自觉
 *
 * 加这一层之前，插件只经 JDBC 读库，连一次写操作都不可能发生；加之后它能**在数据库主机上执行命令**了。因此：
 *
 * 1. **命令只能由本模块的命令构造器产生**，没有任何「接受任意命令字符串」的入口。
 * 2. **参数逐字符校验**（`safeArg`）：只放行路径里真正会用到的字符集；引号、分号、管道、重定向、
 *    `$`、反引号、空格、换行、括号一律**抛错** —— 「把用户输入拼进命令」这条路在类型上就不存在。
 * 3. **每个构造器配一条形态正则**（`OS_PROBE`），`runRemote` 在真正执行前**再验一遍**（纵深防御）：
 *    即使将来有人新增调用路径，非白名单形态的命令也过不去。
 * 4. 全部命令**只读**：`ps` / `stat` / `ss|netstat` / `grep` / `find` / `ls`。
 *    **没有** `rm`/`chmod`/`chown`/`service`/`systemctl`/`kill`，也没有任何写重定向。
 * 5. **口令不会被带回**：明文口令扫描在**本模块内就先做掩码**（`maskSecrets`），
 *    上层只可能拿到「文件:行号 + 已掩码的片段」；报告层是第二道防线（analyze 的 `redact`）。
 *
 * ## 为什么 stdout/stderr 走文件而不是管道
 *
 * 实测教训（09 组）：受限沙箱下用管道捕获子进程输出会 EPERM。这里一律
 * `stdio: ['ignore', <outFd>, <errFd>]`，再从文件读；临时目录用完即删（连不上时也不留）。
 *
 * ## plink 还是 ssh
 *
 * 非交互地传口令，Windows 上只能靠 plink（OpenSSH 不收非交互口令）。代价是口令会出现在
 * plink 的进程参数里 —— **已知弱点**，README 里写明；更稳的做法是改用密钥。
 * plink `-batch` 模式要求主机密钥已知，所以支持 `sshHostKey` 传指纹。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

/** 路径参数允许的字符集。**故意很窄** —— 常见路径足够用，而注入所需的一切都在外面。 */
const SAFE_ARG = /^[A-Za-z0-9._\-/+=:@%~]+$/;

/** 校验一个将用于 shell 的路径参数；不合法就**抛错**（不静默清洗）。 */
export function safeArg(v, what = '参数') {
  const s = String(v ?? '');
  if (s === '') throw new Error(`${what} 为空`);
  if (!SAFE_ARG.test(s)) {
    const bad = [...new Set(s.split('').filter((c) => !SAFE_ARG.test(c)))].join('');
    throw new Error(`${what} 含不允许的字符 «${bad}»：${s}`);
  }
  return s;
}

/** 审计文件保留期的默认要求（天）。**业务决策**，不是标准里写死的数字 —— 可按单位留痕要求覆盖。 */
export const DEFAULT_OS_RETENTION_DAYS = 180;

/** 校验整数（端口 / 天数 / 超时）。 */
export function safeInt(v, what, { min = 1, max = 65535 } = {}) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${what} 非法：${v}`);
  return n;
}

/** 去掉终端控制序列（真机上 `ss`/`dmrman` 会写 OSC/CSI 序列，混进交付件会变成乱码前缀）。 */
const ANSI_OSC = /\u001b\][^\u0007\u001b\r\n]*(?:\u0007|\u001b\\)?/g;
const ANSI_CSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
export function stripAnsi(v) {
  return String(v ?? '').replace(ANSI_OSC, '').replace(ANSI_CSI, '').replace(/\u001b/g, '');
}

/**
 * 口令掩码 —— **本模块的最后一道防线，必须在数据离开本模块之前执行**。
 *
 * 为什么这么紧：明文口令扫描会命中 `disql SYSDBA/xxx@host` 这类行，而它正是「证据」。
 * 要么把口令带进报告，要么就别展示原文 —— 这里选择**先掩码再返回**：
 *   · `用户/口令@` → `用户/***@`（达梦 disql / dmrman 的连接串形态）
 *   · `password=…` / `passwd: …` / `pwd=…` → `***`
 * 上层（analyze 的 `redact`）还有第二道，但**不能依赖它**：掩码必须在源头做。
 */
export function maskSecrets(text) {
  return String(text ?? '')
    .replace(/([A-Za-z0-9_$#]+)\/([^@\s/]{3,})@/g, '$1/***@')
    .replace(/((?:password|passwd|pwd)[A-Za-z_]*)\s*[=:]\s*\S+/gi, '$1=***');
}

/**
 * 命令白名单。每个能力一个构造器 + 一条**形态正则**。
 *
 * 约定：构造器只接受「已经过 safeArg 的路径/整数」，别的什么都不接受。
 * 需要多个路径时用 `stat ... p1 p2 p3`（一次 SSH 往返拿全，减少往返次数也减少暴露面）。
 */
export const OS_PROBE = {
  /** ① 数据库进程：拿到运行账号、安装目录、dm.ini 路径（后续路径都从这里推导，不靠用户拼） */
  proc: {
    build: () => `ps -eo user=,pid=,args= 2>/dev/null | grep -E 'dmserver|dmwatcher' | grep -v grep | head -20`,
    shape: /^ps -eo user=,pid=,args= 2>\/dev\/null \| grep -E 'dmserver\|dmwatcher' \| grep -v grep \| head -20$/,
  },
  /** ② 权限与属主（可带多个路径） */
  perms: {
    build: (paths) => `stat -c '%a %U:%G %n' ${paths.map((p) => safeArg(p, '待查路径')).join(' ')} 2>/dev/null`,
    shape: /^stat -c '%a %U:%G %n' [A-Za-z0-9._\-/+=:@%~ ]+ 2>\/dev\/null$/,
  },
  /**
   * ③ 监听绑定：达梦各服务有没有绑到 0.0.0.0（优先 ss，回退 netstat）。
   *
   * ★ 带 `-p` 取**进程名**。单实例上一台主机只有一个 `dmserver` 在听，只看实例端口就够；
   *   但 **DMDSC 上一台主机同时有好几个达梦服务在听** —— 真机实测 `10.0.0.61`：
   *   7236 `dmserver`（库）、7336 `dmserver`（内部）、7436/7536 `dmasmsvrm`（ASM）、
   *   7936 `dmcss`（集群同步）、4236 `dmap`（助手），**全部绑在 `*`**，而旧实现一条都不判。
   *   对应条款「关闭不需要的系统服务、默认共享和高危端口」，这些端正是集群特有的攻击面。
   *   `-p` 要权限才显示进程名：看不到时进程名为空，判定退回「只判数据库端口」（旧行为）。
   */
  listen: {
    build: () => `(ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null) | head -60`,
    shape: /^\(ss -lntp 2>\/dev\/null \|\| netstat -lntp 2>\/dev\/null\) \| head -60$/,
  },
  /** ④ sshd 基线（只取判定用的几行） */
  sshd: {
    build: () => `grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication|Port)' /etc/ssh/sshd_config 2>/dev/null | head -20`,
    shape: /^grep -Ei '\^\[\[:space:\]\]\*\(PermitRootLogin\|PasswordAuthentication\|PermitEmptyPasswords\|PubkeyAuthentication\|Port\)' \/etc\/ssh\/sshd_config 2>\/dev\/null \| head -20$/,
  },
  /** ⑤ 审计文件清单（文件名 + 日期 + 大小），只列一层，避免在大目录上跑飞 */
  audit: {
    build: (dir) =>
      `find ${safeArg(dir, '审计目录')} -maxdepth 1 -type f -printf '%TY-%Tm-%Td %s %p\\n' 2>/dev/null | sort | head -60`,
    shape: /^find [A-Za-z0-9._\-/+=:@%~]+ -maxdepth 1 -type f -printf '%TY-%Tm-%Td %s %p\\n' 2>\/dev\/null \| sort \| head -60$/,
  },
  /** ⑥ 明文口令痕迹：**只认 `disql`/`dmrman` 连接串形态**（见 CRED_RE 的注释：宽模式会命中证书与文档模板） */
  plaintext: {
    build: (dir) =>
      `grep -rInE --exclude-dir=.git --exclude-dir=tool --exclude-dir=drivers --exclude-dir=client_ssl --exclude-dir=doc --exclude-dir=docs --exclude-dir=samples --exclude=*.log --exclude=*.pem --exclude=*.crt --exclude=*.key '(disql|dmrman|dsql)[^|]*[A-Za-z0-9_$#]+/[^@[:space:]/]{4,}@' ${safeArg(dir, '扫描目录')} 2>/dev/null | head -200`,
    shape:
      /^grep -rInE --exclude-dir=\.git --exclude-dir=tool --exclude-dir=drivers --exclude-dir=client_ssl --exclude-dir=doc --exclude-dir=docs --exclude-dir=samples --exclude=\*\.log --exclude=\*\.pem --exclude=\*\.crt --exclude=\*\.key '\(disql\|dmrman\|dsql\)\[\^\|\]\*\[A-Za-z0-9_\$#\]\+\/\[\^@\[:space:\]\/\]\{4,\}@' [A-Za-z0-9._\-/+=:@%~]+ 2>\/dev\/null \| head -200$/,
  },
  /**
   * ⑦ DM 专用账号的 shell 历史（历史里常有整条 disql 带口令的命令）。
   * ★ 上限 200 而不是 20：真机上 dmdba 的历史里有 **41** 条带口令的 disql，`tail -20` 会把
   *   报告里的「N 处」截成 20（实际显示 5 条），**低报规模**。上限只影响一次 SSH 的输出量，
   *   放大到 200 基本不会再截断；真到 200 时报告会明确写「已达上限」。
   */
  history: {
    build: (homeDir) =>
      `grep -nE 'disql|dmrman|SYSDBA/' ${safeArg(homeDir, '家目录')}/.bash_history 2>/dev/null | tail -200`,
    shape: /^grep -nE 'disql\|dmrman\|SYSDBA\/' [A-Za-z0-9._\-/+=:@%~]+\/\.bash_history 2>\/dev\/null \| tail -200$/,
  },
};

/** 探测用到的全部能力键（顺序即执行顺序；先拿进程信息，再按推导出的路径去查权限）。 */
export const OS_CAP_KEYS = Object.keys(OS_PROBE);

/**
 * 执行一条**已构造好**的远程命令。
 * 两道关：先按 `OS_PROBE` 的形态正则校验（不在白名单里直接抛错），再用 plink 非交互执行。
 * 输出走**文件**而不是管道（沙箱下管道 EPERM，见文件头）。
 */
export function runRemote({ command, host, port = 22, user, password, hostKey, plinkPath = 'plink', timeoutMs = 60000 }) {
  const cmd = String(command ?? '');
  if (!Object.values(OS_PROBE).some((c) => c.shape.test(cmd))) {
    throw new Error(`拒绝执行非白名单形态的命令：${cmd.slice(0, 120)}`);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dm-ossh-'));
  const outFile = path.join(tmp, 'out.txt');
  const errFile = path.join(tmp, 'err.txt');
  const args = ['-ssh', '-batch', '-P', String(safeInt(port, 'SSH 端口')), `${safeArg(user, 'SSH 账号')}@${safeArg(host, 'SSH 主机')}`, '-pw', String(password)];
  if (hostKey) args.push('-hostkey', String(hostKey));
  args.push(cmd);

  const outFd = fs.openSync(outFile, 'w');
  const errFd = fs.openSync(errFile, 'w');
  let res;
  try {
    res = spawnSync(plinkPath, args, { stdio: ['ignore', outFd, errFd], windowsHide: true, timeout: timeoutMs });
  } finally {
    fs.closeSync(outFd);
    fs.closeSync(errFd);
  }
  const readQuiet = (p) => {
    try {
      return fs.readFileSync(p, 'utf8');
    } catch {
      return '';
    }
  };
  const stdout = stripAnsi(readQuiet(outFile));
  const stderr = stripAnsi(readQuiet(errFile));
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* 清理失败不影响结果 */
  }
  return { ok: (res?.status ?? -1) === 0, status: res?.status ?? -1, stdout, stderr, error: res?.error ? String(res.error.message ?? res.error) : null };
}

/**
 * 把 plink 自身的失败翻译成「怎么修」。
 *
 * 为什么要单独判：口令错、主机密钥未确认、plink 不在 PATH 这三种情况下，远端命令**根本没执行**，
 * 输出为空。若不区分，就会报成「命令无输出」或更糟 —— 报成「没发现问题」（那是在谎报原因）。
 * 判据只认 plink 自己那几句**特征明确**的报错（远端脚本不会这么写）。
 */
export function sshTroubleNote(res) {
  if (!res) return 'SSH 未执行';
  if (res.error) return `**SSH 层无法执行**（连 plink 都没跑起来）：${res.error}`;
  const text = `${res.stderr}\n${res.stdout}`;
  const hit = /Access denied|Unable to open connection|No supported authentication|Host key|host key|Connection refused|Connection timed out|Network error/i.test(text);
  if (!hit) return null;
  const keyHint = /Host key|host key/i.test(text)
    ? '\n> plink 在 `-batch` 模式下要求主机密钥已知：用 `sshHostKey` 传指纹（形如 `ssh-ed25519 255 SHA256:…`），或先在主机上手工接受一次。'
    : '';
  return `**SSH 连接失败**：${text.split('\n').map((l) => l.trim()).filter(Boolean).slice(0, 2).join(' ')}${keyHint}`;
}

// ------------------------------------------------------------------ 解析（纯函数，可离线测）

/** `ps -eo user=,pid=,args=` → 数据库进程列表。 */
export function parseProc(text) {
  const out = [];
  for (const line of String(text ?? '').split('\n')) {
    const m = /^(\S+)\s+(\d+)\s+(\S.*)$/.exec(line.trim());
    if (!m) continue;
    const args = m[3];
    if (!/dmserver|dmwatcher/.test(args)) continue;
    const pathMatch = /(\/[^\s]*?)\/(dm\.ini|dmwatcher\.ini)(\s|$)/.exec(args);
    out.push({
      user: m[1],
      pid: m[2],
      cmd: args.split(' ')[0],
      args,
      /** 实例配置文件绝对路径（后续目录都由它推导） */
      iniPath: pathMatch ? `${pathMatch[1]}/${pathMatch[2]}` : null,
    });
  }
  return out;
}

/** `stat -c '%a %U:%G %n'` → 每个路径的权限与属主。 */
export function parseStat(text) {
  const out = [];
  for (const line of String(text ?? '').split('\n')) {
    const m = /^([0-7]{3,4})\s+([^:\s]+):([^\s]+)\s+(.+)$/.exec(line.trim());
    if (!m) continue;
    out.push({ mode: m[1], owner: m[2], group: m[3], path: m[4].trim() });
  }
  return out;
}

/** `ss -lntp` / `netstat -lntp` 输出 → 监听项（含进程名，取不到则 `proc` 为 null）。兼容两种表头与 IPv6 形态。 */
export function parseListen(text) {
  const out = [];
  for (const line of String(text ?? '').split('\n')) {
    const t = line.trim();
    if (!/^(LISTEN|tcp)/i.test(t)) continue;
    const m = /(\S+):(\d+)\s+\S+/.exec(t);
    if (!m) continue;
    out.push({ addr: m[1], port: Number(m[2]), proc: procOfListenLine(t) });
  }
  return out;
}

/**
 * 从一行监听项里取**进程名**（拿不到返回 `null`）。
 *
 * 两种输出格式都认（先命中的先用）：
 *   · `ss -lntp`      → `users:(("dmserver",pid=4094,fd=4))`
 *   · `netstat -lntp` → `… LISTEN 4094/dmserver`
 *
 * 拿不到是**正常情况**（非 root 看不到 socket 属主），所以调用方必须能退回「只知道端口」。
 */
export function procOfListenLine(line) {
  const t = String(line ?? '');
  const ss = /users:\(\("([^"]+)"/.exec(t);
  if (ss) return ss[1];
  const ns = /\s\d+\/([A-Za-z0-9_.\-]+)\s*$/.exec(t);
  return ns ? ns[1] : null;
}

/** sshd_config 的行 → 键值（key 统一小写，便于判定）。 */
export function parseSshd(text) {
  const out = {};
  for (const line of String(text ?? '').split('\n')) {
    const m = /^\s*([A-Za-z]+)\s+(\S+)/.exec(line);
    if (!m) continue;
    out[m[1].toLowerCase()] = m[2];
  }
  return out;
}

/** `find … -printf '%TY-%Tm-%Td %s %p'` → 审计文件清单（含最旧/最新日期）。 */
export function parseAuditFiles(text) {
  const files = [];
  for (const line of String(text ?? '').split('\n')) {
    const m = /^(\d{4}-\d{2}-\d{2})\s+(\d+)\s+(.+)$/.exec(line.trim());
    if (!m) continue;
    files.push({ date: m[1], size: Number(m[2]), path: m[3].trim() });
  }
  files.sort((a, b) => a.date.localeCompare(b.date));
  return files;
}

/**
 * 「账号/口令@」形态 —— 与 `plaintext` 命令里的 grep 模式同源，但**多两道断言**。
 *
 * ★ 真机两次误报（2026-10-12，DMDSC `10.0.0.61`）教出来的：
 *   ① 宽模式命中 DM 自带 `client_ssl/<主题>/client-cert.pem` 里的
 *      `Subject: … CN=DEVELOP/dmeng@dameng.com` —— **证书主题不是口令**；
 *      判据：用户名前一个字符不能是 `=`（`CN=DEVELOP/…` 前面就是 `=`）。
 *   ② 还会命中 XPath 表达式（`select="/testsuites/testcase/@package"`）与 Python 驱动源码里的
 *      **模板串**（`'%s/%s@%s'`、docstring 里的 `"user/xxx@ip:port/schema"`）—— 都不是真实口令；
 *      判据：**同一行必须出现 `disql`/`dmrman`/`dsql`**（本项的语义就是「DM 客户端连接串」），
 *      且口令段不能含引号 / `{}` / `%` / `$` 这些代码字符。
 *   收紧后真机剩下 5 处**真命中**：`~/.bash_history` 里手打的 `disql appuser/xxx@10.0.0.61:7236`。
 *
 * 为什么解析时还要再判一次（而不是只靠 grep）：真实路径上 grep 已过滤，但解析器不该依赖
 * 「输入一定干净」—— 演示数据、换扫描命令、手工喂文本时，非命中行会被误算成命中。
 * 掩码后的 `***` 只有 3 字符，因此本正则对「已掩码文本」天然幂等，不会重复计数。
 */
const CLIENT_RE = /\b(disql|dmrman|dsql)\b/;
const CRED_RE = /(?<![=\w$%])([A-Za-z][A-Za-z0-9_$#]{0,30})\/([^@\s/'"<>{}%$]{4,})@/;
/** 一行同时具备「DM 客户端命令」与「账号/口令@」才算命中。 */
const isCredentialLine = (line) => CLIENT_RE.test(line) && CRED_RE.test(line);

/**
 * 明文口令扫描结果 → **已掩码**的命中清单。
 * 输入形如 `/<path>/start.sh:12:disql SYSDBA/xxx@1.2.3.4:5236`（grep -n 的形态）。
 */
export function parsePlaintextHits(text) {
  const hits = [];
  for (const line of String(text ?? '').split('\n')) {
    const t = line.trim();
    if (!t || !isCredentialLine(t)) continue;
    const m = /^(.*?):(\d+):(.*)$/.exec(t);
    const file = m ? m[1] : t;
    const lineno = m ? Number(m[2]) : null;
    const snippet = maskSecrets(m ? m[3] : '');
    hits.push({ file, lineno, snippet: snippet.slice(0, 160) });
  }
  return hits;
}

/**
 * shell 历史命中（同样掩码；只保留行号与片段，绝不返回整条命令的口令）。
 * 历史里没有 `grep` 那层过滤，但同样要求「DM 客户端命令 + 连接串」同时出现。
 */
export function parseHistoryHits(text) {
  const hits = [];
  for (const line of String(text ?? '').split('\n')) {
    const t = line.trim();
    if (!t || !isCredentialLine(t)) continue;
    const m = /^(\d+):(.*)$/.exec(t);
    hits.push({ lineno: m ? Number(m[1]) : null, snippet: maskSecrets(m ? m[2] : t).slice(0, 160) });
  }
  return hits;
}

/**
 * 推导 **DM 安装根目录**（DM_HOME）。
 *
 * ★ 真机校准（2026-10-12，DMDSC `10.0.0.61`）：DSC 的实例配置**不是** `.../data/DAMENG/dm.ini`，
 *   而是 `.../data/DSC01/DSC01_conf/dm.ini`（多一层目录）。按 `<DM_HOME>/data/<实例>/dm.ini` 硬套会算错，
 *   于是「明文口令扫描」会去扫一个不存在的目录（表现为「没发现痕迹」——**谎报合规**）。
 *   最稳的判据是**可执行文件路径**：`<DM_HOME>/bin/dmserver` → 去掉 `/bin/xxx` 即 DM_HOME；
 *   dm.ini 的启发式只作退路（用非贪婪匹配，容忍 DSC 的多层结构）。
 */
export function deriveDmHome(proc) {
  const cmd = String(proc?.cmd ?? '');
  const byCmd = /^(.*)\/bin\/[^/]+$/.exec(cmd);
  if (byCmd) return byCmd[1];
  const ini = proc?.iniPath ?? null;
  if (!ini) return null;
  const byIni = /^(.*?)\/data\/.*\/dm\.ini$/.exec(ini);
  return byIni ? byIni[1] : ini.replace(/\/[^/]+$/, '');
}

/**
 * 推导要查权限的目录与文件。
 * 目的：**路径由进程信息推导，不由用户拼**，既少一类输入风险，也少一次往返。
 *
 * 真机（DSC）实测布局：`<DM_HOME>/{bin,data}`、`<DM_HOME>/data/DSC01/{dmdcr.ini,dmasvrmal.ini,dminit.ini}`、
 * `<DM_HOME>/data/DSC01/DSC01_conf/dm.ini`。所以 dm.ini 的**所在目录**是实例配置目录，
 * 它的父目录是实例数据目录，`.../data` 之前是安装目录 —— 三层都要看。
 */
export function derivePaths(proc) {
  const paths = new Set();
  const ini = proc?.iniPath ?? null;
  if (ini) {
    const confDir = ini.replace(/\/[^/]+$/, ''); // 实例配置目录（dm.ini 所在）
    let instDir = confDir.replace(/\/[^/]+$/, ''); // 实例数据目录（DSC: …/data/DSC01；单实例: …/data）
    let dataDir = /\/data$/.test(instDir) ? instDir : instDir.replace(/\/[^/]+$/, '');
    if (instDir === dataDir) instDir = confDir; // 单实例：data 下直接就是实例目录
    const home = deriveDmHome(proc);
    paths.add(ini);
    paths.add(confDir);
    if (instDir !== confDir) paths.add(instDir);
    if (dataDir && dataDir !== instDir && dataDir !== confDir) paths.add(dataDir);
    if (home && home !== dataDir) paths.add(home);
    // 审计文件默认落在**实例配置目录**下的 audit（DM 只在启用审计后才创建该目录）
    paths.add(`${confDir}/audit`);
    for (const f of ['dmarch.ini', 'dmdcr.ini', 'dmmal.ini', 'dmasvrmal.ini', 'dmwatcher.ini']) {
      paths.add(`${instDir}/${f}`);
      if (confDir !== instDir) paths.add(`${confDir}/${f}`);
    }
  }
  return [...paths];
}

/** 家目录（给 `.bash_history` 用）：优先数据库进程的运行账号。 */
export function deriveHomeDir(proc, sshUser) {
  const u = proc?.user || sshUser;
  if (!u || u === 'root') return '/root';
  return `/home/${u}`;
}

/**
 * 审计文件保留情况。
 *
 * 判据：目录里**最旧**的审计文件距今多少天 —— 比要求保留期还新，说明保留期不够（早期的记录已经被滚掉）。
 * `retentionDays` 是**业务决策**（默认由 `DEFAULT_THRESHOLDS.osRetentionDays` 给出），不是标准里写死的数字。
 */
export function judgeAuditRetention(files, retentionDays, today = new Date()) {
  if (!files?.length) return { state: 'empty', ageDays: null, detail: '审计目录里没有任何文件' };
  const oldest = files[0];
  const d = new Date(`${oldest.date}T00:00:00Z`);
  const ageDays = Math.floor((today.getTime() - d.getTime()) / 86400000);
  return {
    state: ageDays >= retentionDays ? 'ok' : 'short',
    ageDays,
    oldest,
    newest: files[files.length - 1],
    detail: `最旧审计文件 ${oldest.date}（距今约 ${ageDays} 天），最新 ${files[files.length - 1].date}`,
  };
}

/**
 * 采一次主机侧事实。
 *
 * 顺序刻意如此：**先用 `ps` 定位实例**，再由它推导出要查权限的目录 —— 路径不由用户拼，
 * 少一类输入风险，也少一次往返。整套动作在真机上约 7 次 SSH 往返（每次一个 plink 进程），
 * 所以只在**配了 SSH 时**才做；没配就根本不调用本函数（上层直接判「未启用」）。
 *
 * `run` 可注入（离线自检用假的 run 就能跑全部分支，不需要真机）。
 */
export function probeOs({ ssh, retentionDays = DEFAULT_OS_RETENTION_DAYS, dbPort = null, extraPaths = [], timeoutMs = 60000, run = runRemote } = {}) {
  const base = { host: ssh?.host, port: ssh?.port ?? 22, user: ssh?.user, password: ssh?.password, hostKey: ssh?.hostKey, plinkPath: ssh?.plinkPath, timeoutMs };
  const outputs = {};
  const commands = [];
  const call = (key, command) => {
    const res = run({ command, ...base });
    commands.push({ key, command, status: res.status, ok: res.ok, stderr: String(res.stderr ?? '').trim().slice(0, 400) });
    outputs[key] = res.stdout ?? '';
    return res;
  };

  // ① 进程（也是「SSH 到底通不通」的探针）
  const procRes = call('proc', OS_PROBE.proc.build());
  const trouble = sshTroubleNote(procRes);
  if (trouble) {
    // 连不上就没必要再跑后面 6 条：直接把 7 个 plink 超时叠起来只会让用户白等
    return { state: 'unknown', detail: trouble, facts: null, commands, trouble };
  }
  const procList = parseProc(outputs.proc);
  const primary = procList.find((p) => /dmserver/.test(p.args)) ?? procList[0] ?? null;

  // ② 权限与属主（路径由 ① 推导 + 用户补充）
  const paths = [...new Set([...derivePaths(primary), ...extraPaths])];
  if (paths.length) call('perms', OS_PROBE.perms.build(paths.slice(0, 20)));

  // ③④ 监听与 sshd 基线（固定命令，与实例路径无关）
  call('listen', OS_PROBE.listen.build());
  call('sshd', OS_PROBE.sshd.build());

  // ⑤ 审计目录（推导出来的那个）
  const auditDir = paths.find((p) => /\/audit$/.test(p)) ?? null;
  if (auditDir) call('audit', OS_PROBE.audit.build(auditDir));

  // ⑥⑦ 明文口令痕迹：DM 安装目录 + 运行账号的家目录历史
  const homeDir = deriveHomeDir(primary, base.user);
  const dmHome = deriveDmHome(primary);
  if (dmHome) call('plaintext', OS_PROBE.plaintext.build(dmHome));
  call('history', OS_PROBE.history.build(homeDir));

  const facts = buildOsFacts({ outputs, ssh: base, extraPaths });
  /**
   * 每条命令的**退出码**：必须留下来。
   *
   * ★ 真机教训（2026-10-13）：清理掉明文口令后，`grep` 因「没有命中」而返回 **1 且无输出** ——
   *   与「命令根本没跑 / 被拒」在输出上完全一样。原先只按「输出是否为空」判断，
   *   于是把「扫了但干净」误报成「未取到」。`grep` 的语义：0=有命中、1=无命中（**正常**）、≥2=出错。
   */
  facts.exit = Object.fromEntries(commands.map((c) => [c.key, c.status]));
  facts.dbPort = dbPort ?? null;
  facts.retentionDays = retentionDays;
  facts.retention = judgeAuditRetention(facts.auditFiles, retentionDays);
  facts.auditDir = auditDir;
  facts.homeDir = homeDir;
  facts.dmHome = dmHome;
  return { state: 'ok', detail: `已在 ${base.user}@${base.host} 上执行 ${commands.length} 条只读命令`, facts, commands, trouble: null };
}


/**
 * 主机指纹：把一串命令输出整理成**判定用的结构化事实**（含每条命令的原始回显，供报告展开复核）。
 * 纯函数：给定同一批文本，结论一定相同 —— 这样离线自检才能覆盖真机的判定分支。
 */
export function buildOsFacts({ outputs = {}, ssh = {}, extraPaths = [] }) {
  const procList = parseProc(outputs.proc);
  const primary = procList.find((p) => /dmserver/.test(p.args)) ?? procList[0] ?? null;
  const paths = [...new Set([...derivePaths(primary), ...extraPaths])];
  const stat = parseStat(outputs.perms);
  const listen = parseListen(outputs.listen);
  const sshd = parseSshd(outputs.sshd);
  const auditFiles = parseAuditFiles(outputs.audit);
  const plaintextHits = parsePlaintextHits(outputs.plaintext);
  const historyHits = parseHistoryHits(outputs.history);
  return {
    sshUser: ssh.user ?? null,
    hosts: { host: ssh.host ?? null, port: ssh.port ?? null },
    processes: procList,
    primaryProcess: primary,
    /**
     * 命令回显（已 stripAnsi **且已掩码**）：报告里按命令分块展开。
     * ★ 这里必须掩码：`plaintext` 那条命令的输出**就是**带口令的连接串，
     *   原样留着等于把口令又搬进了结论对象（报告 / JSON 都可能落盘）。
     *   掩码放在数据离开本模块之前，是这一层的硬约束（见文件头第 5 条）。
     */
    outputs: Object.fromEntries(Object.entries(outputs).map(([k, v]) => [k, maskSecrets(String(v ?? '').trim())])),
    paths,
    /** 目录 / 配置文件分列：权限检查对两者的判据不同（目录看 other 写，ini 看 other 读） */
    dirPaths: paths.filter((p) => !/\.ini$/.test(p)),
    filePaths: paths.filter((p) => /\.ini$/.test(p)),
    stat,
    listen,
    sshd,
    auditFiles,
    auditOldest: auditFiles[0] ?? null,
    auditNewest: auditFiles[auditFiles.length - 1] ?? null,
    plaintextHits,
    historyHits,
  };
}
