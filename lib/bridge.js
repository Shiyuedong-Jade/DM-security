/**
 * Node ↔ Java 桥（形态沿用 09 组的 `bridge.js`，已在该组真机验证过）。
 *
 * 为什么用「SQL 文件进 / JSON 文件出」而不是 stdio 传协议：
 *   1. Windows 下 Java 的 stdin/stdout 编码容易出错，而中文对象名/库名很常见；
 *      用文件可以把编码钉死在 UTF-8，出问题还能直接看中间产物。
 *   2. `stdio: 'ignore'`：不捕获子进程输出就不会去开管道 —— 受限沙箱下用管道
 *      捕获子进程输出会 EPERM，而我们本来也不需要（Java 把错误写进 JSON 的 `fatal`）。
 *      需要看 stderr 时重定向到**文件**（开文件不是开管道，因此被允许）。
 *
 * 安全：桥本身只放行 `SELECT` / `WITH`，其余语句一律拒绝并计入 `rejected`。
 * 本插件在此之上不再提供任何写操作入口。
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');

/** 工作目录：放驱动、编译产物与临时文件。 */
export function defaultHome() {
  return process.env.DM_SECURITY_HOME || path.join(os.homedir(), '.dsh', 'dm-security');
}

export function ensureHome(home) {
  for (const sub of ['drivers', 'java', 'runtime', 'classes']) {
    fs.mkdirSync(path.join(home, sub), { recursive: true });
  }
  return home;
}

/** 找 JDBC 驱动 jar。达梦驱动是商业组件、不随插件分发，必须由用户放置。 */
export function findDriverJar(home, explicit) {
  const candidates = [];
  if (explicit) candidates.push(explicit);
  const dir = path.join(home, 'drivers');
  if (fs.existsSync(dir)) {
    for (const f of fs.readdirSync(dir)) {
      if (/^DmJdbcDriver\d*\.jar$/i.test(f)) candidates.push(path.join(dir, f));
    }
  }
  for (const c of candidates) {
    if (c && fs.existsSync(c)) return c;
  }
  return null;
}

export function findJava(explicit) {
  const home = explicit || process.env.JAVA_HOME;
  return home ? path.join(home, 'bin', 'java') : 'java';
}

function findJavac(javaHome) {
  return javaHome ? path.join(javaHome, 'bin', 'javac') : 'javac';
}

let compiledCache = null;

/** 编译只读桥（一次即可，结果缓存在工作目录）。 */
export function ensureBridgeCompiled(home, driverJar, javaHome) {
  const src = path.join(PKG, 'assets', 'java', 'DmQuery.java');
  const classesDir = path.join(home, 'classes');
  const classFile = path.join(classesDir, 'DmQuery.class');
  const srcStat = fs.statSync(src);
  if (compiledCache && compiledCache.classFile === classFile && compiledCache.mtime === srcStat.mtimeMs && fs.existsSync(classFile)) {
    return { classesDir, classFile };
  }
  if (fs.existsSync(classFile) && fs.statSync(classFile).mtimeMs >= srcStat.mtimeMs) {
    compiledCache = { classFile, mtime: srcStat.mtimeMs };
    return { classesDir, classFile };
  }
  const javac = findJavac(javaHome);
  const args = ['-encoding', 'UTF-8', '-cp', driverJar, '-d', classesDir, src];
  const errFile = path.join(home, 'runtime', 'javac.err.txt');
  const r = runCapturingStderrToFile(javac, args, 120000, errFile);
  if (r.status !== 0) {
    const detail = fs.existsSync(errFile) ? fs.readFileSync(errFile, 'utf8').trim() : '(无 stderr)';
    throw new Error(
      `编译 JDBC 桥失败（javac 退出码 ${r.status}）。\n` +
        `请确认已安装 JDK（不只是 JRE），且 JAVA_HOME 指向它。\n` +
        `命令: ${javac} ${args.join(' ')}\n` +
        `javac 输出:\n${detail}`,
    );
  }
  compiledCache = { classFile, mtime: srcStat.mtimeMs };
  return { classesDir, classFile };
}

function runIgnoringStdio(cmd, args, timeoutMs) {
  return spawnSync(cmd, args, { stdio: 'ignore', windowsHide: true, timeout: timeoutMs });
}

function runCapturingStderrToFile(cmd, args, timeoutMs, errFile) {
  fs.mkdirSync(path.dirname(errFile), { recursive: true });
  const fd = fs.openSync(errFile, 'w');
  try {
    return spawnSync(cmd, args, { stdio: ['ignore', 'ignore', fd], windowsHide: true, timeout: timeoutMs });
  } finally {
    fs.closeSync(fd);
  }
}

/** 执行一批 SQL（`;` 分隔），返回逐条结果。 */
export async function runSql(opts) {
  const home = ensureHome(opts.home || defaultHome());
  const driverJar = findDriverJar(home, opts.driverJar);
  if (!driverJar) {
    throw new Error(
      '未找到达梦 JDBC 驱动。达梦驱动是商业组件、不随插件分发，需要你手动放置：\n' +
        `  把达梦安装目录下的 dmdbms/drivers/jdbc/DmJdbcDriver8.jar（或 DmJdbcDriver18.jar）\n` +
        `  复制到 ${path.join(home, 'drivers')}\\ 下即可。`,
    );
  }
  const { classesDir } = ensureBridgeCompiled(home, driverJar, opts.javaHome);

  const stamp = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const sqlFile = path.join(home, 'runtime', `req-${stamp}.sql`);
  const outFile = path.join(home, 'runtime', `res-${stamp}.json`);
  fs.writeFileSync(sqlFile, opts.sqlText, 'utf8');

  const java = findJava(opts.javaHome);
  const cp = `${classesDir}${path.delimiter}${driverJar}`;
  const args = [
    '-Dfile.encoding=UTF-8',
    '-cp',
    cp,
    'DmQuery',
    String(opts.host),
    String(opts.port),
    String(opts.user),
    String(opts.password),
    sqlFile,
    outFile,
    String(opts.maxRows ?? 2000),
    String(opts.timeoutSec ?? 180),
  ];

  /** 本次调用是否成功读到结果（决定临时文件是删掉还是留下排查） */
  let ok = false;
  try {
    const r = runIgnoringStdio(java, args, (opts.timeoutSec ?? 180) * 1000 + 30000);
    if (!fs.existsSync(outFile)) {
      throw new Error(
        `JDBC 桥没有产出结果文件（java 退出码 ${r.status}）。` +
          `常见原因：java 不在 PATH、驱动 jar 与 JDK 版本不匹配、或连接被拒绝。\n` +
          `命令: ${java} ${args.join(' ')}\n` +
          `（本次的请求/结果文件已保留，便于排查：${sqlFile} 、${outFile}）`,
      );
    }
    const parsed = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    ok = true;
    return parsed;
  } finally {
    try {
      /**
       * ★ 成功即删：`res-*.json` 里是**未经脱敏**的原始结果（脱敏发生在 analyze 层，晚于这里落盘）。
       *   真机逐条查过：当前没有口令散列落盘（命中的 "PASSWORD" 是 DBA_PROFILES.RESOURCE_TYPE 的取值），
       *   但 `SYSUSERS` 有 PASSWORD/OLD_PASSWORD/ENCRYPT_KEY —— 一旦某条查询降级到 `SELECT *` 就会带上。
       *   所以正常路径直接删掉，不留痕；**失败时保留**（路径已写进上面的错误信息）以便排查，
       *   并由下面的兜底清理保证 runtime/ 不会无限增长。
       */
      if (ok) {
        fs.rmSync(sqlFile, { force: true });
        fs.rmSync(outFile, { force: true });
      }
      const runtime = path.join(home, 'runtime');
      const files = fs.readdirSync(runtime).map((f) => path.join(runtime, f));
      if (files.length > 50) {
        files
          .map((f) => ({ f, t: fs.statSync(f).mtimeMs }))
          .sort((a, b) => a.t - b.t)
          .slice(0, files.length - 50)
          .forEach(({ f }) => fs.rmSync(f, { force: true }));
      }
    } catch {
      /* 清理失败不影响主流程 */
    }
  }
}

/**
 * 带降级的批量执行。
 *
 * 为什么要「批量 + 按需重试」：每次调用都要起一个 JVM（约 1 秒），逐条跑会让一次评估慢十几倍。
 *   第 1 轮：所有查询的首选语句一次跑完；
 *   第 2..n 轮：只把报「无效的列名/表名」的那些换成备选，再批量跑一次。
 */
export async function runQueries(opts, queries) {
  const out = {};
  const needsRetry = [];

  const batch = async (list) => {
    if (list.length === 0) return [];
    const sqlText = list.map((q) => `${q.sql};`).join('\n') + '\n';
    const res = await runSql({ ...opts, sqlText });
    if (res.fatal) throw new Error(`JDBC 桥致命错误: ${res.fatal}`);
    return res.statements ?? [];
  };

  const first = await batch(queries.map((q) => ({ sql: q.sql })));
  queries.forEach((q, i) => {
    const r = first[i] ?? { columns: null, rows: [], error: 'NO_RESULT' };
    if (r.error && (q.fallbacks?.length ?? 0) > 0 && isNameError(r.error)) {
      needsRetry.push({ key: q.key, idx: i, fallbacks: q.fallbacks });
    }
    out[q.key] = { columns: r.columns ?? null, rows: r.rows ?? [], error: r.error ?? null, sqlUsed: q.sql };
  });

  let depth = 0;
  while (needsRetry.length > 0 && depth < 5) {
    const list = needsRetry.map((n) => ({ sql: n.fallbacks[depth] })).filter((x) => x.sql);
    if (list.length === 0) break;
    const got = await batch(list);
    const still = [];
    let k = 0;
    for (const n of needsRetry) {
      if (!n.fallbacks[depth]) continue;
      const r = got[k++] ?? { columns: null, rows: [], error: 'NO_RESULT' };
      if (!r.error) {
        out[n.key] = { columns: r.columns ?? null, rows: r.rows ?? [], error: null, sqlUsed: n.fallbacks[depth] };
      } else if (depth + 1 < n.fallbacks.length && isNameError(r.error)) {
        still.push(n);
      } else {
        out[n.key] = { columns: r.columns ?? null, rows: r.rows ?? [], error: r.error ?? null, sqlUsed: n.fallbacks[depth] };
      }
    }
    needsRetry.length = 0;
    needsRetry.push(...still);
    depth++;
  }

  return out;
}

/**
 * 只有「名字不对」才值得换一条 SQL；权限/连接类错误换语句也没用。
 *
 * ⚠️ 2026-10-12 真机修正（10.0.0.40）：达梦对「列不存在」的报错是
 *    **「无法解析的成员访问表达式[S.SESSION_PER_USER]」**，原来的正则只认
 *    「无效的列名」，导致降级链在真机上**一次都没触发** —— 首选的扩展列查询失败后
 *    整条证据被丢弃，`pwdPolicy` 直接变成「未取到」。
 *    这里把达梦实际用到的几种措辞都收进来。
 */
export function isNameError(msg) {
  return /无效的列名|无效的表或视图名|无效的表名|无效的标识符|无法解析的成员访问表达式|不存在的列|invalid column|invalid identifier|invalid expression|unknown column|does not exist/i.test(
    String(msg),
  );
}
