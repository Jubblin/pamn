import { parseXml, type XNode } from "./xml";

export interface Script { id: string; output: string }
export interface Port {
  protocol: string; port: number; state: string; reason?: string;
  service?: { name: string; product?: string; version?: string; extrainfo?: string; tunnel?: string; cpe: string[] };
  scripts: Script[];
}
export interface OsMatch { name: string; accuracy: number }
export interface Hop { ttl: number; ip: string; rtt?: number; host?: string }
export interface Host {
  addr: string; addrType: string; mac?: string; vendor?: string;
  hostnames: string[]; status: string; reason?: string;
  ports: Port[]; os: OsMatch[]; uptimeSeconds?: number; hops: Hop[]; hostScripts: Script[];
}
export interface NmapResult {
  args: string; version?: string; start?: number;
  scanInfo: { type: string; protocol: string; services: string }[];
  hosts: Host[];
  stats: { up?: number; down?: number; total?: number; elapsed?: number; summary?: string; exit?: string };
  /** true when the XML had no closing </nmaprun> (interrupted scan or partial file) */
  partial: boolean;
}

const kids = (n: XNode | undefined, name: string) => n?.children.filter((c) => c.name === name) ?? [];
const kid = (n: XNode | undefined, name: string) => n?.children.find((c) => c.name === name);
const num = (s?: string) => (s === undefined || s === "" || isNaN(+s) ? undefined : +s);
const scripts = (n?: XNode): Script[] => kids(n, "script").map((s) => ({ id: s.attrs.id ?? "", output: s.attrs.output ?? "" }));

function parseHost(h: XNode): Host {
  const addrs = kids(h, "address");
  const ip = addrs.find((a) => a.attrs.addrtype !== "mac") ?? addrs[0];
  const mac = addrs.find((a) => a.attrs.addrtype === "mac");
  const st = kid(h, "status");
  const svc = (p: XNode): Port["service"] => {
    const s = kid(p, "service");
    return s && { name: s.attrs.name ?? "", product: s.attrs.product, version: s.attrs.version,
      extrainfo: s.attrs.extrainfo, tunnel: s.attrs.tunnel, cpe: kids(s, "cpe").map((c) => c.text.trim()) };
  };
  return {
    addr: ip?.attrs.addr ?? "", addrType: ip?.attrs.addrtype ?? "",
    mac: mac?.attrs.addr, vendor: mac?.attrs.vendor,
    hostnames: kids(kid(h, "hostnames"), "hostname").map((x) => x.attrs.name).filter(Boolean),
    status: st?.attrs.state ?? "unknown", reason: st?.attrs.reason,
    ports: kids(kid(h, "ports"), "port").map((p) => ({
      protocol: p.attrs.protocol ?? "tcp", port: num(p.attrs.portid) ?? 0,
      state: kid(p, "state")?.attrs.state ?? "unknown", reason: kid(p, "state")?.attrs.reason,
      service: svc(p), scripts: scripts(p),
    })),
    os: kids(kid(h, "os"), "osmatch").map((o) => ({ name: o.attrs.name ?? "", accuracy: num(o.attrs.accuracy) ?? 0 })),
    uptimeSeconds: num(kid(h, "uptime")?.attrs.seconds),
    hops: kids(kid(h, "trace"), "hop").map((t) => ({ ttl: num(t.attrs.ttl) ?? 0, ip: t.attrs.ipaddr ?? "", rtt: num(t.attrs.rtt), host: t.attrs.host })),
    hostScripts: scripts(kid(h, "hostscript")),
  };
}

/** Parse nmap -oX output (also Zenmap-saved files). Tolerates truncated XML. */
export function parseNmapXml(xml: string): NmapResult {
  const run = kid(parseXml(xml), "nmaprun");
  if (!run) throw new Error("Not nmap XML: no <nmaprun> element");
  const fin = kid(kid(run, "runstats"), "finished");
  const hosts = kid(kid(run, "runstats"), "hosts");
  return {
    args: run.attrs.args ?? "", version: run.attrs.version, start: num(run.attrs.start),
    scanInfo: kids(run, "scaninfo").map((s) => ({ type: s.attrs.type ?? "", protocol: s.attrs.protocol ?? "", services: s.attrs.services ?? "" })),
    hosts: kids(run, "host").map(parseHost),
    stats: { up: num(hosts?.attrs.up), down: num(hosts?.attrs.down), total: num(hosts?.attrs.total),
      elapsed: num(fin?.attrs.elapsed), summary: fin?.attrs.summary, exit: fin?.attrs.exit },
    partial: !/<\/nmaprun\s*>/.test(xml),
  };
}
