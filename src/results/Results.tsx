import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import type { Host, NmapResult } from "../nmap";
import Compare, { type Other } from "./Compare";
import { download } from "./files";
import { NO_FILTERS, bestOs, filterHosts, groupByService, hostName, openPorts, osFamilies, serviceNames, toCsv, toJson, versionText, type Filters } from "./model";
import { rovingKeys } from "../ui/roving";
import Topology from "./Topology";
import "./results.css";

type View = "hosts" | "services" | "map" | "compare";
const VIEWS: [View, string][] = [["hosts", "Devices"], ["services", "Services"], ["map", "Route map"], ["compare", "Compare"]];

interface Props { result: NmapResult; live: boolean; xml?: string; name: string; others: Other[] }

export default function Results({ result, live, xml, name, others }: Props) {
  const [view, setView] = useState<View>("hosts");
  const [f, setF] = useState<Filters>(NO_FILTERS);
  const [sel, setSel] = useState<string | undefined>();
  const hosts = useMemo(() => filterHosts(result.hosts, f), [result.hosts, f]);
  const upHosts = useMemo(() => result.hosts.filter((h) => h.status === "up"), [result.hosts]);
  const selected = result.hosts.find((h) => h.addr === sel && hosts.includes(h)) ?? hosts[0];
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) => setF((x) => ({ ...x, [k]: v }));
  const menu = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const close = (e: Event) => { const m = menu.current; if (m?.open && !m.contains(e.target as Node)) m.open = false; };
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, []);
  const base = name.replace(/[^\w.-]+/g, "_") || "scan";
  const pick = (addr: string) => { setSel(addr); setF((x) => ({ ...x, status: "all", text: "", openOnly: false, port: "", service: "", os: "" })); setView("hosts"); };

  return (
    <section className="card results-card" aria-label="Scan results">
      <div className="res-head">
        <div role="tablist" aria-label="Result views" className="seg" onKeyDown={rovingKeys}>
          {VIEWS.map(([v, label]) => <button key={v} role="tab" id={"res-tab-" + v} aria-controls="res-panel" aria-selected={view === v} tabIndex={view === v ? 0 : -1} className={view === v ? "on" : ""} onClick={() => setView(v)}>{label}</button>)}
        </div>
        {live && <span className="live"><i />Live — updating as devices finish</span>}
        <div className="res-actions">
          <details className="menu" ref={menu}
            onToggle={(e) => { if (e.currentTarget.open) e.currentTarget.querySelector<HTMLButtonElement>(".menu-pop button:not(:disabled)")?.focus(); }}
            onKeyDown={(e) => { if (e.key === "Escape" && e.currentTarget.open) { e.currentTarget.open = false; e.currentTarget.querySelector("summary")?.focus(); } }}>
            <summary className="btn sm" aria-label="Save or export">Save / export ▾</summary>
            <div className="menu-pop" role="group" aria-label="Export format" onClick={(e) => { const d = e.currentTarget.parentElement as HTMLDetailsElement; d.open = false; d.querySelector("summary")?.focus(); }}>
              <button disabled={!xml} title={xml ? "" : "XML is available once the scan finishes"} onClick={() => xml && download(`${base}.xml`, xml, "text/xml")}>Nmap XML (.xml)</button>
              <button onClick={() => download(`${base}.csv`, toCsv(result), "text/csv")}>Spreadsheet (.csv)</button>
              <button onClick={() => download(`${base}.json`, toJson(result), "application/json")}>JSON (.json)</button>
            </div>
          </details>
        </div>
      </div>

      <div role="tabpanel" id="res-panel" aria-labelledby={"res-tab-" + view}>
      {view === "hosts" && (
        <>
          <div className="filters">
            <input className="input sm search" type="search" aria-label="Search results" placeholder="Search address, name, service, system…" value={f.text} onChange={(e) => set("text", e.target.value)} />
            <select className="input sm" aria-label="Status" value={f.status} onChange={(e) => set("status", e.target.value as Filters["status"])}>
              <option value="up">Online</option><option value="down">Offline</option><option value="all">All devices</option>
            </select>
            <select className="input sm" aria-label="Service" value={f.service} onChange={(e) => set("service", e.target.value)}>
              <option value="">Any service</option>{serviceNames(result.hosts).map((s) => <option key={s}>{s}</option>)}
            </select>
            <select className="input sm" aria-label="Operating system" value={f.os} onChange={(e) => set("os", e.target.value)}>
              <option value="">Any system</option>{osFamilies(result.hosts).map((s) => <option key={s}>{s}</option>)}
            </select>
            <input className="input sm port" inputMode="numeric" aria-label="Open port number" placeholder="Port" value={f.port} onChange={(e) => set("port", e.target.value.replace(/\D/g, ""))} />
            <label className="check"><input type="checkbox" checked={f.openOnly} onChange={(e) => set("openOnly", e.target.checked)} /> Has open ports</label>
          </div>
          {hosts.length === 0
            ? <p className="empty">{result.hosts.length === 0 ? (live ? "Waiting for the first device to finish…" : "No devices found.") : "Nothing matches these filters."} {result.hosts.length > 0 && <button className="link" onClick={() => setF({ ...NO_FILTERS, status: "all" })}>Clear filters</button>}</p>
            : (
              <div className="split">
                <ul className="hlist" aria-label="Devices">
                  {hosts.map((h) => {
                    const n = openPorts(h).length;
                    return (
                      <li key={h.addr}>
                        <button className={"hrow" + (h === selected ? " on" : "")} aria-current={h === selected} onClick={() => setSel(h.addr)}>
                          <span className={"dot " + (h.status === "up" ? "done" : "")} aria-label={h.status} />
                          <span className="hmain"><strong>{hostName(h)}</strong><small>{h.hostnames[0] ? h.addr : bestOs(h) ?? h.vendor ?? ""}</small></span>
                          <span className="count" title="Open ports">{n}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
                {selected && <HostDetail h={selected} />}
              </div>
            )}
        </>
      )}

      {view === "services" && <Services hosts={upHosts} onPick={pick} />}
      {view === "map" && <Topology hosts={result.hosts} onPick={pick} />}
      {view === "compare" && <Compare current={result} others={others} />}
      </div>
    </section>
  );
}

function Services({ hosts, onPick }: { hosts: Host[]; onPick: (addr: string) => void }) {
  const groups = useMemo(() => groupByService(hosts), [hosts]);
  if (groups.length === 0) return <p className="empty">No open services found yet.</p>;
  return (
    <ul className="svc-list">
      {groups.map((g) => (
        <li key={g.name} className="svc">
          <div className="svc-h"><strong>{g.name}</strong><span className="muted small">{g.entries.length} port{g.entries.length === 1 ? "" : "s"} on {new Set(g.entries.map((e) => e.host.addr)).size} device{new Set(g.entries.map((e) => e.host.addr)).size === 1 ? "" : "s"}</span></div>
          <div className="svc-body">
            {g.entries.map(({ host, port }) => (
              <button key={host.addr + port.protocol + port.port} className="svc-entry" onClick={() => onPick(host.addr)} title={versionText(port) || undefined}>
                <span>{hostName(host)}</span><code>{port.port}/{port.protocol}</code>{versionText(port) && <small className="muted">{versionText(port)}</small>}
              </button>
            ))}
          </div>
        </li>
      ))}
    </ul>
  );
}

function HostDetail({ h }: { h: Host }) {
  const [openScripts, setOpenScripts] = useState<string | null>(null);
  const ports = [...h.ports].sort((a, b) => (a.state === "open" ? 0 : 1) - (b.state === "open" ? 0 : 1) || a.port - b.port);
  return (
    <article className="detail" key={h.addr}>
      <header>
        <h3>{hostName(h)}</h3>
        <span className={"chip " + (h.status === "up" ? "ok" : "")}>{h.status === "up" ? "Online" : h.status === "down" ? "Offline" : h.status}</span>
      </header>
      <dl className="facts">
        <dt>Address</dt><dd><code>{h.addr}</code></dd>
        {h.hostnames.length > 1 && <><dt>Names</dt><dd>{h.hostnames.join(", ")}</dd></>}
        {h.mac && <><dt>Hardware</dt><dd><code>{h.mac}</code>{h.vendor && ` · ${h.vendor}`}</dd></>}
        {h.uptimeSeconds !== undefined && <><dt>Uptime</dt><dd>{Math.round(h.uptimeSeconds / 3600)} hours</dd></>}
      </dl>

      {h.os.length > 0 && (
        <section><h4>Operating system guesses</h4>
          <ul className="os">{h.os.slice(0, 4).map((o) => (
            <li key={o.name}><span>{o.name}</span><span className="acc" aria-label={`${o.accuracy}% likely`}><i style={{ width: `${o.accuracy}%` }} /></span><small>{o.accuracy}%</small></li>
          ))}</ul>
        </section>
      )}

      <section><h4>Ports</h4>
        {ports.length === 0 ? <p className="muted small">No ports were scanned or found for this device.</p> : (
          <table className="ports">
            <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Details</th></tr></thead>
            <tbody>{ports.map((p) => {
              const k = p.protocol + p.port;
              return (
                <Fragment key={k}>
                  <tr>
                    <td><code>{p.port}/{p.protocol}</code></td>
                    <td><span className={"state " + p.state.split("|")[0]}>{p.state}</span></td>
                    <td>{p.service?.name ?? <span className="muted">—</span>}</td>
                    <td>{versionText(p) || <span className="muted">—</span>}{p.scripts.length > 0 && <> <button className="link" aria-expanded={openScripts === k} onClick={() => setOpenScripts(openScripts === k ? null : k)}>{p.scripts.length} check{p.scripts.length === 1 ? "" : "s"}</button></>}</td>
                  </tr>
                  {openScripts === k && <tr><td colSpan={4}><Scripts list={p.scripts} /></td></tr>}
                </Fragment>
              );
            })}</tbody>
          </table>
        )}
      </section>

      {h.hostScripts.length > 0 && <section><h4>Device checks</h4><Scripts list={h.hostScripts} /></section>}

      {h.hops.length > 0 && (
        <section><h4>Route to this device</h4>
          <ol className="hops">{h.hops.map((hop) => <li key={hop.ttl}><span className="muted small">{hop.ttl}</span><code>{hop.host ?? hop.ip}</code>{hop.rtt !== undefined && <small className="muted">{hop.rtt} ms</small>}</li>)}</ol>
        </section>
      )}
    </article>
  );
}

const Scripts = ({ list }: { list: { id: string; output: string }[] }) => (
  <div className="scripts">{list.map((s) => <div key={s.id}><strong>{s.id}</strong><pre>{s.output.trim()}</pre></div>)}</div>
);
