import type { Host, NmapResult, Port } from "../nmap";

export const hostName = (h: Host) => h.hostnames[0] ?? h.addr;
export const openPorts = (h: Host) => h.ports.filter((p) => p.state === "open");
export const bestOs = (h: Host) => h.os[0]?.name;
const osFamily = (h: Host) => bestOs(h)?.split(/\s+/)[0];
const svcName = (p: Port) => p.service?.name || "unknown";
export const portKey = (p: Port) => `${p.protocol}/${p.port}`;
export const versionText = (p: Port) => [p.service?.product, p.service?.version, p.service?.extrainfo && `(${p.service.extrainfo})`].filter(Boolean).join(" ");

export interface Filters { text: string; status: "all" | "up" | "down"; openOnly: boolean; port: string; service: string; os: string }
export const NO_FILTERS: Filters = { text: "", status: "up", openOnly: false, port: "", service: "", os: "" };

export function filterHosts(hosts: Host[], f: Filters): Host[] {
  const q = f.text.trim().toLowerCase();
  const port = f.port.trim();
  return hosts.filter((h) => {
    if (f.status !== "all" && h.status !== f.status) return false;
    const open = openPorts(h);
    if (f.openOnly && open.length === 0) return false;
    if (port && !open.some((p) => String(p.port) === port)) return false;
    if (f.service && !open.some((p) => svcName(p) === f.service)) return false;
    if (f.os && osFamily(h) !== f.os) return false;
    if (!q) return true;
    const hay = [h.addr, h.mac, h.vendor, ...h.hostnames, bestOs(h), ...open.map((p) => `${p.port} ${svcName(p)} ${versionText(p)}`)];
    return hay.some((s) => s?.toLowerCase().includes(q));
  });
}

export const serviceNames = (hosts: Host[]) => [...new Set(hosts.flatMap((h) => openPorts(h).map(svcName)))].sort();
export const osFamilies = (hosts: Host[]) => [...new Set(hosts.map(osFamily).filter((x): x is string => !!x))].sort();

export interface ServiceGroup { name: string; entries: { host: Host; port: Port }[] }
/** Open ports grouped by service name; biggest groups first. */
export function groupByService(hosts: Host[]): ServiceGroup[] {
  const m = new Map<string, ServiceGroup>();
  for (const host of hosts) for (const port of openPorts(host)) {
    const n = svcName(port);
    (m.get(n) ?? m.set(n, { name: n, entries: [] }).get(n)!).entries.push({ host, port });
  }
  return [...m.values()].sort((a, b) => b.entries.length - a.entries.length || a.name.localeCompare(b.name));
}

// ---- compare -------------------------------------------------------------
export interface PortDiff { addr: string; port: Port; before?: Port }
export interface ScanDiff {
  newHosts: Host[]; goneHosts: Host[];
  opened: PortDiff[]; closed: PortDiff[]; changed: PortDiff[];
}
const up = (r: NmapResult) => new Map(r.hosts.filter((h) => h.status === "up").map((h) => [h.addr, h]));
const sig = (p: Port) => `${svcName(p)}|${versionText(p)}`;

/** `before` -> `after`. Ports are compared on open state and service/version. */
export function compareScans(before: NmapResult, after: NmapResult): ScanDiff {
  const a = up(before), b = up(after);
  const d: ScanDiff = { newHosts: [], goneHosts: [], opened: [], closed: [], changed: [] };
  for (const [addr, h] of b) if (!a.has(addr)) d.newHosts.push(h);
  for (const [addr, h] of a) if (!b.has(addr)) d.goneHosts.push(h);
  for (const [addr, hb] of b) {
    const ha = a.get(addr);
    if (!ha) continue; // brand new hosts are reported as hosts, not port-by-port
    const pa = new Map(openPorts(ha).map((p) => [portKey(p), p]));
    const pb = new Map(openPorts(hb).map((p) => [portKey(p), p]));
    for (const [k, p] of pb) {
      const old = pa.get(k);
      if (!old) d.opened.push({ addr, port: p });
      else if (sig(old) !== sig(p)) d.changed.push({ addr, port: p, before: old });
    }
    for (const [k, p] of pa) if (!pb.has(k)) d.closed.push({ addr, port: p });
  }
  return d;
}
export const diffCount = (d: ScanDiff) => d.newHosts.length + d.goneHosts.length + d.opened.length + d.closed.length + d.changed.length;

// ---- export --------------------------------------------------------------
// Banners come from the network, so neutralise spreadsheet formulas.
const cell = (s: string | number | undefined) => {
  let t = String(s ?? "");
  if (/^[=+\-@\t\r]/.test(t)) t = "'" + t;
  return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
};
export function toCsv(r: NmapResult): string {
  const rows: (string | number | undefined)[][] = [["address", "hostname", "status", "protocol", "port", "state", "service", "product", "version"]];
  for (const h of r.hosts) {
    const base = [h.addr, h.hostnames.join(" "), h.status];
    if (h.ports.length === 0) rows.push([...base, "", "", "", "", "", ""]);
    for (const p of h.ports) rows.push([...base, p.protocol, p.port, p.state, p.service?.name, p.service?.product, p.service?.version]);
  }
  return rows.map((r) => r.map(cell).join(",")).join("\n") + "\n";
}
export const toJson = (r: NmapResult) => JSON.stringify(r, null, 2);

// ---- live results --------------------------------------------------------
/** Builds hosts from nmap's normal text output, so results appear while a scan runs (XML only exists at the end). */
export function parseLive(lines: string[]): NmapResult {
  const hosts: Host[] = [];
  let cur: Host | undefined;
  for (const line of lines) {
    const rep = /^Nmap scan report for (?:(\S+) \(([^)]+)\)|(\S+))/.exec(line);
    if (rep) {
      cur = { addr: rep[2] ?? rep[3], addrType: "", hostnames: rep[1] ? [rep[1]] : [], status: "up", ports: [], os: [], hops: [], hostScripts: [] };
      hosts.push(cur);
      continue;
    }
    const pm = /^(\d+)\/(tcp|udp|sctp)\s+(\S+)\s*(\S*)\s*(.*)$/.exec(line);
    if (pm && cur) cur.ports.push({ protocol: pm[2], port: +pm[1], state: pm[3], scripts: [], service: pm[4] ? { name: pm[4], product: pm[5] || undefined, cpe: [] } : undefined });
  }
  return { args: "", scanInfo: [], hosts, stats: {}, partial: true };
}

// ---- topology ------------------------------------------------------------
export interface TopoNode { id: string; label: string; sub?: string; kind: "you" | "hop" | "unknown" | "host"; depth: number; y: number; parent?: string }
/** Tree rooted at "You": one path per host following its traceroute hops. */
export function buildTopology(hosts: Host[]): { nodes: TopoNode[]; maxDepth: number; hasTrace: boolean } {
  const nodes = new Map<string, TopoNode>([["you", { id: "you", label: "This computer", kind: "you", depth: 0, y: 0 }]]);
  const kids = new Map<string, string[]>();
  const add = (n: Omit<TopoNode, "y">) => {
    if (nodes.has(n.id)) return;
    nodes.set(n.id, { ...n, y: 0 });
    kids.set(n.parent!, [...(kids.get(n.parent!) ?? []), n.id]);
  };
  let hasTrace = false;
  for (const h of hosts.filter((x) => x.status === "up")) {
    let parent = "you", depth = 1, ttl = 0;
    const hops = [...h.hops].sort((a, b) => a.ttl - b.ttl).filter((x) => x.ip && x.ip !== h.addr);
    if (h.hops.length) hasTrace = true;
    for (const hop of hops) {
      for (; ttl + 1 < hop.ttl; ttl++) { // silent routers leave gaps in the numbering
        const id = `?${parent}>${ttl + 1}`;
        add({ id, label: "?", sub: "no reply", kind: "unknown", depth: depth++, parent });
        parent = id;
      }
      ttl = hop.ttl;
      add({ id: hop.ip, label: hop.host ?? hop.ip, sub: hop.host ? hop.ip : undefined, kind: "hop", depth, parent });
      parent = hop.ip; depth++;
    }
    add({ id: h.addr, label: hostName(h), sub: h.hostnames[0] ? h.addr : undefined, kind: "host", depth, parent });
  }
  let row = 0;
  const place = (id: string) => {
    const c = kids.get(id) ?? [];
    const n = nodes.get(id)!;
    if (c.length === 0) { n.y = row++; return; }
    c.forEach(place);
    n.y = (nodes.get(c[0])!.y + nodes.get(c[c.length - 1])!.y) / 2;
  };
  place("you");
  const all = [...nodes.values()];
  return { nodes: all, maxDepth: Math.max(...all.map((n) => n.depth)), hasTrace };
}
