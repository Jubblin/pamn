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

// Lowercased searchable text per host, built once (hosts are immutable once parsed) so each keystroke is a plain substring test.
const hayCache = new WeakMap<Host, string>();
const searchText = (h: Host): string => {
  let t = hayCache.get(h);
  if (t === undefined) {
    t = [h.addr, h.mac, h.vendor, ...h.hostnames, bestOs(h), ...openPorts(h).map((p) => `${p.port} ${svcName(p)} ${versionText(p)}`)]
      .filter(Boolean).join("\n").toLowerCase();
    hayCache.set(h, t);
  }
  return t;
};

export function filterHosts(hosts: Host[], f: Filters): Host[] {
  const q = f.text.trim().toLowerCase();
  const port = f.port.trim();
  const needOpen = f.openOnly || !!port || !!f.service;
  return hosts.filter((h) => {
    if (f.status !== "all" && h.status !== f.status) return false;
    if (f.os && osFamily(h) !== f.os) return false;
    const open = needOpen ? openPorts(h) : [];
    if (f.openOnly && open.length === 0) return false;
    if (port && !open.some((p) => String(p.port) === port)) return false;
    if (f.service && !open.some((p) => svcName(p) === f.service)) return false;
    if (!q) return true;
    return searchText(h).includes(q);
  });
}

export const serviceNames = (hosts: Host[]) => [...new Set(hosts.flatMap((h) => openPorts(h).map(svcName)))].sort();
export const osFamilies = (hosts: Host[]) => [...new Set(hosts.map(osFamily).filter((x): x is string => !!x))].sort();

export interface ServiceGroup { name: string; entries: { host: Host; port: Port }[]; devices: number }
/** Open ports grouped by service name; biggest groups first. */
export function groupByService(hosts: Host[]): ServiceGroup[] {
  const m = new Map<string, ServiceGroup>();
  for (const host of hosts) for (const port of openPorts(host)) {
    const n = svcName(port);
    const g = m.get(n) ?? m.set(n, { name: n, entries: [], devices: 0 }).get(n)!;
    if (g.entries[g.entries.length - 1]?.host !== host) g.devices++; // hosts are visited one at a time
    g.entries.push({ host, port });
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
const REPORT = /^Nmap scan report for (?:(\S+) \(([^)]+)\)|(\S+))/;
const PORT_LINE = /^(\d+)\/(tcp|udp|sctp)\s+(\S+)\s*(\S*)\s*(.*)$/;

/**
 * Incremental parser for nmap's normal text output, so results appear while a scan runs (XML only exists at the end).
 * Only lines added since the previous call are examined, and the previous result object is returned when
 * they change nothing, so memoised views downstream don't recompute.
 */
export function createLiveParser() {
  let work: Host[] = [];
  let dirty = false;
  let result: NmapResult = { args: "", scanInfo: [], hosts: work, stats: {}, partial: true };
  let seen: string[] = [];
  const consume = (line: string) => {
    const rep = REPORT.exec(line);
    if (rep) {
      dirty = true;
      work.push({ addr: rep[2] ?? rep[3], addrType: "", hostnames: rep[1] ? [rep[1]] : [], status: "up", ports: [], os: [], hops: [], hostScripts: [] });
      return;
    }
    const cur = work[work.length - 1];
    const pm = cur && PORT_LINE.exec(line);
    if (!pm) return;
    const port: Port = { protocol: pm[2], port: +pm[1], state: pm[3], scripts: [], service: pm[4] ? { name: pm[4], product: pm[5] || undefined, cpe: [] } : undefined };
    dirty = true;
    work[work.length - 1] = { ...cur, ports: [...cur.ports, port] };
  };
  return (lines: string[]): NmapResult => {
    const n = seen.length;
    let from = 0;
    if (lines === seen) from = n;
    else if (n > 1 && lines.length === n && lines[n - 2] === seen[n - 1] && lines[0] === seen[1]) from = n - 1; // capped log scrolled by one
    else if (n > 0 && lines.length >= n && lines[n - 1] === seen[n - 1]) from = n; // appended
    else if (n > 0 || work.length > 0) { work = []; dirty = true; } // log was reset
    seen = lines;
    for (let i = from; i < lines.length; i++) consume(lines[i]);
    if (dirty) { result = { ...result, hosts: work.slice() }; dirty = false; }
    return result;
  };
}
export const parseLive = (lines: string[]): NmapResult => createLiveParser()(lines);

// ---- topology ------------------------------------------------------------
export interface TopoNode { id: string; label: string; sub?: string; kind: "you" | "hop" | "unknown" | "host"; depth: number; y: number; parent?: string }
/** Tree rooted at "You": one path per host following its traceroute hops. */
export function buildTopology(hosts: Host[]): { nodes: TopoNode[]; maxDepth: number; hasTrace: boolean } {
  const nodes = new Map<string, TopoNode>([["you", { id: "you", label: "This computer", kind: "you", depth: 0, y: 0 }]]);
  const kids = new Map<string, string[]>();
  const add = (n: Omit<TopoNode, "y">) => {
    if (nodes.has(n.id)) return;
    nodes.set(n.id, { ...n, y: 0 });
    const k = kids.get(n.parent!);
    if (k) k.push(n.id); else kids.set(n.parent!, [n.id]);
  };
  let hasTrace = false;
  for (const h of hosts) {
    if (h.status !== "up") continue;
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
