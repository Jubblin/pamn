export interface NmapOptions {
  targets: string[];
  scanType?: string;        // e.g. "-sS", "-sT", "-sU", "-sn"
  serviceVersion?: boolean; // -sV
  os?: boolean;             // -O
  aggressive?: boolean;     // -A
  skipPing?: boolean;       // -Pn
  noDns?: boolean;          // -n
  traceroute?: boolean;     // --traceroute
  defaultScripts?: boolean; // -sC
  scripts?: string;         // --script=<value>
  ports?: string;           // -p
  fast?: boolean;           // -F
  topPorts?: number;        // --top-ports
  timing?: number;          // -T0..5
  verbose?: number;         // -v count
  /** everything not modelled above, verbatim and in order */
  extra: string[];
}

const SCAN_TYPES = new Set(["-sS", "-sT", "-sU", "-sn", "-sA", "-sF", "-sN", "-sX", "-sW", "-sM", "-sY", "-sZ", "-sO", "-sI"]);
// unknown flags that take a separate value argument (so it isn't mistaken for a target)
const VALUE_FLAGS = new Set(["-oN", "-oX", "-oG", "-oA", "-oS", "-iL", "-iR", "-e", "-S", "-g", "-D", "-b", "-PS", "-PA", "-PU", "-PY", "-PO", "-PE", "-PP", "-PM",
  "--exclude", "--excludefile", "--max-retries", "--host-timeout", "--min-rate", "--max-rate", "--data-length", "--source-port", "--dns-servers",
  "--script-args", "--script-timeout", "--min-parallelism", "--max-parallelism", "--min-hostgroup", "--max-hostgroup", "--scan-delay", "--max-scan-delay",
  "--initial-rtt-timeout", "--min-rtt-timeout", "--max-rtt-timeout", "--version-intensity", "--ttl", "--datadir", "--servicedb", "--versiondb", "--scanflags", "--proxies"]);

export function tokenize(s: string): string[] {
  const out: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2] ?? m[3]);
  return out;
}
const quote = (t: string) => (/[\s"'\;&|<>()$`]/.test(t) || t === "" ? `"${t.replace(/(["\\$`])/g, "\\$1")}"` : t);

export function parseCommand(cmd: string): NmapOptions {
  const o: NmapOptions = { targets: [], extra: [] };
  const t = tokenize(cmd);
  if (t[0] === "nmap") t.shift();
  for (let i = 0; i < t.length; i++) {
    const a = t[i];
    if (SCAN_TYPES.has(a) && !o.scanType) o.scanType = a;
    else if (a === "-sV") o.serviceVersion = true;
    else if (a === "-sC") o.defaultScripts = true;
    else if (a === "-O") o.os = true;
    else if (a === "-A") o.aggressive = true;
    else if (a === "-Pn") o.skipPing = true;
    else if (a === "-n") o.noDns = true;
    else if (a === "-F") o.fast = true;
    else if (a === "--traceroute") o.traceroute = true;
    else if (a === "-p" && i + 1 < t.length) o.ports = t[++i];
    else if (/^-p[^-]/.test(a)) o.ports = a.slice(2);
    else if (a === "--top-ports" && i + 1 < t.length && !isNaN(+t[i + 1])) o.topPorts = +t[++i];
    else if (/^--top-ports=\d+$/.test(a)) o.topPorts = +a.slice(12);
    else if (/^-T[0-5]$/.test(a)) o.timing = +a[2];
    else if (/^-v+$/.test(a)) o.verbose = (o.verbose ?? 0) + a.length - 1;
    else if (a === "--script" && i + 1 < t.length) o.scripts = t[++i];
    else if (a.startsWith("--script=")) o.scripts = a.slice(9);
    else if (a.startsWith("-")) {
      o.extra.push(a);
      if (VALUE_FLAGS.has(a) && i + 1 < t.length) o.extra.push(t[++i]);
    } else o.targets.push(a);
  }
  return o;
}

export function buildCommand(o: NmapOptions): string {
  const p = ["nmap"];
  if (o.scanType) p.push(o.scanType);
  if (o.serviceVersion) p.push("-sV");
  if (o.defaultScripts) p.push("-sC");
  if (o.os) p.push("-O");
  if (o.aggressive) p.push("-A");
  if (o.skipPing) p.push("-Pn");
  if (o.noDns) p.push("-n");
  if (o.traceroute) p.push("--traceroute");
  if (o.scripts) p.push(`--script=${quote(o.scripts)}`);
  if (o.ports) p.push("-p", quote(o.ports));
  if (o.fast) p.push("-F");
  if (o.topPorts !== undefined) p.push("--top-ports", String(o.topPorts));
  if (o.timing !== undefined) p.push(`-T${o.timing}`);
  if (o.verbose) p.push("-" + "v".repeat(o.verbose));
  p.push(...o.extra.map(quote), ...o.targets.map(quote));
  return p.join(" ");
}
