import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseNmapXml } from "../nmap";
import { NO_FILTERS, buildTopology, compareScans, filterHosts, groupByService, parseLive, toCsv } from "./model";

const fx = (n: string) => parseNmapXml(readFileSync(new URL(`../nmap/fixtures/${n}`, import.meta.url), "utf8"));
const host = (addr: string, ports: [number, string, string?][], hops: [number, string][] = []) =>
  `<host><status state="up"/><address addr="${addr}" addrtype="ipv4"/><ports>${ports.map(([p, s, v]) => `<port protocol="tcp" portid="${p}"><state state="open"/><service name="${s}" ${v ? `version="${v}"` : ""}/></port>`).join("")}</ports><trace>${hops.map(([t, ip]) => `<hop ttl="${t}" ipaddr="${ip}"/>`).join("")}</trace></host>`;
const scan = (...h: string[]) => parseNmapXml(`<nmaprun>${h.join("")}</nmaprun>`);

describe("real nmap output", () => {
  it("live text parse agrees with the final XML", () => {
    const txt = readFileSync(new URL("./fixtures/real-output.txt", import.meta.url), "utf8").split("\n");
    const live = parseLive(txt), xml = parseNmapXml(readFileSync(new URL("./fixtures/real.xml", import.meta.url), "utf8"));
    const key = (r: typeof live) => r.hosts.map((h) => `${h.addr}:${h.ports.filter((p) => p.state === "open").map((p) => p.port).join(",")}`);
    expect(live.hosts.length).toBe(2);
    expect(key(live)).toEqual(key(xml));
  });
});

describe("results model", () => {
  it("filters and groups fixtures", () => {
    const r = fx("services.xml");
    expect(filterHosts(r.hosts, { ...NO_FILTERS, service: "ssh" }).length).toBe(1);
    expect(filterHosts(r.hosts, { ...NO_FILTERS, port: "9" }).length).toBe(0);
    expect(filterHosts(r.hosts, { ...NO_FILTERS, status: "all", text: "localhost" }).length).toBe(1);
    expect(groupByService(r.hosts).find((g) => g.name === "ssh")?.entries.length).toBe(1);
    expect(filterHosts(fx("os.xml").hosts, { ...NO_FILTERS, os: "nonexistent" }).length).toBe(0);
  });

  it("compare: new/gone hosts, opened/closed/changed ports", () => {
    const a = scan(host("10.0.0.1", [[22, "ssh", "8.0"], [80, "http"]]), host("10.0.0.2", [[22, "ssh"]]));
    const b = scan(host("10.0.0.1", [[22, "ssh", "9.0"], [443, "https"]]), host("10.0.0.3", [[22, "ssh"]]));
    const d = compareScans(a, b);
    expect(d.newHosts.map((h) => h.addr)).toEqual(["10.0.0.3"]);
    expect(d.goneHosts.map((h) => h.addr)).toEqual(["10.0.0.2"]);
    expect(d.opened.map((x) => x.port.port)).toEqual([443]);
    expect(d.closed.map((x) => x.port.port)).toEqual([80]);
    expect(d.changed.map((x) => x.port.port)).toEqual([22]);
    const same = compareScans(a, a);
    expect(same.opened.length + same.closed.length + same.changed.length + same.newHosts.length).toBe(0);
  });

  it("csv escapes quotes and formulas", () => {
    const r = scan(`<host><status state="up"/><address addr="1.1.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="=cmd|x, &quot;y&quot;"/></port></ports></host>`);
    expect(toCsv(r).split("\n")[1]).toBe(`1.1.1.1,,up,tcp,80,open,http,"'=cmd|x, ""y""",`);
  });

  it("parses live output into hosts", () => {
    const r = parseLive(["Starting Nmap", "Nmap scan report for router.lan (192.168.1.1)", "Host is up (0.001s latency).", "", "PORT   STATE SERVICE", "22/tcp open  ssh", "80/tcp closed http", "", "Nmap scan report for 192.168.1.9", "443/tcp open https nginx 1.2"]);
    expect(r.hosts.map((h) => h.addr)).toEqual(["192.168.1.1", "192.168.1.9"]);
    expect(r.hosts[0].hostnames).toEqual(["router.lan"]);
    expect(r.hosts[0].ports.map((p) => p.state)).toEqual(["open", "closed"]);
    expect(r.hosts[1].ports[0].service?.product).toBe("nginx 1.2");
  });

  it("topology shares hops and fills gaps", () => {
    const r = scan(host("10.0.0.5", [], [[1, "10.0.0.1"], [3, "10.9.9.9"]]), host("10.0.0.6", [], [[1, "10.0.0.1"]]));
    const t = buildTopology(r.hosts);
    expect(t.hasTrace).toBe(true);
    expect(t.nodes.filter((n) => n.kind === "hop" && n.id === "10.0.0.1").length).toBe(1);
    expect(t.nodes.some((n) => n.kind === "unknown")).toBe(true);
    expect(t.nodes.find((n) => n.id === "10.0.0.5")!.depth).toBe(4);
    expect(buildTopology(scan(host("1.1.1.1", [])).hosts).hasTrace).toBe(false);
  });
});
