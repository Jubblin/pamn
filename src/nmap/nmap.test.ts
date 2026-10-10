import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildCommand, parseCommand, parseNmapXml } from "./index";

const fx = (n: string) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), "utf8");

describe("parseNmapXml", () => {
  it("ping scan", () => {
    const r = parseNmapXml(fx("ping.xml"));
    expect(r.hosts.length).toBe(2);
    expect(r.hosts[0].status).toBe("up");
    expect(r.hosts[0].addr).toBe("127.0.0.1");
    expect(r.stats.total).toBe(2);
    expect(r.partial).toBe(false);
  });
  it("port + service scan", () => {
    const h = parseNmapXml(fx("services.xml")).hosts[0];
    expect(h.hostnames).toContain("localhost");
    const ssh = h.ports.find((p) => p.port === 22)!;
    expect(ssh.state).toBe("open");
    expect(ssh.service?.name).toBe("ssh");
    expect(ssh.service?.product).toBe("OpenSSH");
    expect(ssh.service?.cpe[0]).toMatch(/^cpe:/);
  });
  it("os + traceroute + scripts", () => {
    const h = parseNmapXml(fx("os.xml")).hosts[0];
    expect(h.os[0]).toEqual({ name: "Linux 3.2 - 4.9", accuracy: 100 });
    expect(h.hops.map((x) => x.ttl)).toEqual([1, 2, 3]);
    expect(h.hops[1]).toMatchObject({ ip: "10.0.0.1", rtt: 8.5, host: "gw.isp.net" });
    expect(h.uptimeSeconds).toBe(1234567);
    expect(h.ports.find((p) => p.port === 80)!.scripts[0]).toEqual({ id: "http-title", output: "Go ahead and ScanMe!" });
    expect(h.ports.find((p) => p.port === 22)!.scripts[0].output).toContain("2048 20:3d");
  });
  it("tolerates truncated XML", () => {
    const x = fx("os.xml");
    const r = parseNmapXml(x.slice(0, x.indexOf('<port protocol="tcp" portid="80"') + 40));
    expect(r.partial).toBe(true);
    expect(r.hosts[0].ports[0].port).toBe(22);
  });
  it("rejects non-nmap input", () => {
    expect(() => parseNmapXml("<html/>")).toThrow();
  });
});

describe("command", () => {
  const cases = [
    "nmap -sS -sV -O -p 1-1000 -T4 -Pn 10.0.0.0/24",
    "nmap -A -v scanme.nmap.org",
    "nmap -sT --top-ports 100 --script=vuln,safe host1 host2",
    "nmap -F -oX out.xml --max-retries 2 --weird-flag 192.168.0.1",
    'nmap -p "80,443" --script-args "a=b c" example.com',
  ];
  for (const c of cases)
    it(`round-trips: ${c}`, () => {
      const o = parseCommand(c);
      expect(parseCommand(buildCommand(o))).toEqual(o);
    });
  it("maps flags and preserves unknowns", () => {
    const o = parseCommand("nmap -sS -p80 -T3 -oX out.xml --weird 1.2.3.4");
    expect(o).toMatchObject({ scanType: "-sS", ports: "80", timing: 3, targets: ["1.2.3.4"], extra: ["-oX", "out.xml", "--weird"] });
    expect(buildCommand(o)).toContain("-oX out.xml --weird 1.2.3.4");
  });
});
