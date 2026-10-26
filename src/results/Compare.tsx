import { useMemo, useRef, useState } from "react";
import { parseNmapXml, type Host, type NmapResult } from "../nmap";
import { compareScans, diffCount, hostName, versionText, type PortDiff } from "./model";

export interface Other { label: string; result: NmapResult }

const svc = (p: PortDiff["port"]) => [p.service?.name, versionText(p)].filter(Boolean).join(" · ");

export default function Compare({ current, others }: { current: NmapResult; others: Other[] }) {
  const [pick, setPick] = useState("");
  const [file, setFile] = useState<Other | null>(null);
  const [err, setErr] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const base = file ?? others[+pick] ?? null;
  const baseResult = base?.result;
  const d = useMemo(() => (baseResult ? compareScans(baseResult, current) : null), [baseResult, current]);

  const load = async (f?: File) => {
    if (!f) return;
    try { setFile({ label: f.name, result: parseNmapXml(await f.text()) }); setErr(""); }
    catch (e) { setErr(`${f.name}: ${e instanceof Error ? e.message : e}`); }
  };

  return (
    <div className="compare">
      <div className="cmp-pick">
        <label className="field"><span>Compare this scan with an earlier one</span>
          <select className="input sm" value={file ? "file" : pick} onChange={(e) => { setFile(null); setPick(e.target.value); }}>
            <option value="">Choose a scan…</option>
            {others.map((o, i) => <option key={i} value={i}>{o.label}</option>)}
            {file && <option value="file">{file.label}</option>}
          </select></label>
        <button className="btn sm" onClick={() => input.current?.click()}>Open a saved file…</button>
        <input ref={input} type="file" accept=".xml,text/xml" hidden onChange={(e) => { load(e.target.files?.[0]); e.target.value = ""; }} />
      </div>
      {err && <p className="help err" role="alert">{err}</p>}
      {!d && <p className="empty">Pick another scan to see what changed: new or missing devices, and ports that opened, closed or changed.</p>}
      {d && (diffCount(d) === 0
        ? <p className="empty ok-note">No differences. Both scans found the same devices and open ports.</p>
        : <>
          <div className="chips">
            <Chip n={d.newHosts.length} label="new devices" k="add" /><Chip n={d.goneHosts.length} label="devices gone" k="rem" />
            <Chip n={d.opened.length} label="ports opened" k="add" /><Chip n={d.closed.length} label="ports closed" k="rem" /><Chip n={d.changed.length} label="changed" k="chg" />
          </div>
          <ul className="diff">
            {d.newHosts.map((h) => <Row key={"n" + h.addr} k="add" tag="New device" main={hostName(h)} sub={hostSummary(h)} />)}
            {d.goneHosts.map((h) => <Row key={"g" + h.addr} k="rem" tag="Gone" main={hostName(h)} sub={hostSummary(h)} />)}
            {d.opened.map((x) => <Row key={"o" + x.addr + x.port.port} k="add" tag="Opened" main={`${x.addr}  ${x.port.port}/${x.port.protocol}`} sub={svc(x.port)} />)}
            {d.closed.map((x) => <Row key={"c" + x.addr + x.port.port} k="rem" tag="Closed" main={`${x.addr}  ${x.port.port}/${x.port.protocol}`} sub={svc(x.port)} />)}
            {d.changed.map((x) => <Row key={"h" + x.addr + x.port.port} k="chg" tag="Changed" main={`${x.addr}  ${x.port.port}/${x.port.protocol}`} sub={`${svc(x.before!)}  →  ${svc(x.port)}`} />)}
          </ul>
        </>)}
    </div>
  );
}
const hostSummary = (h: Host) => { const n = h.ports.filter((p) => p.state === "open").length; return h.hostnames[0] ? `${h.addr} · ${n} open` : `${n} open port${n === 1 ? "" : "s"}`; };
const Chip = ({ n, label, k }: { n: number; label: string; k: string }) => <span className={"cchip " + k + (n ? "" : " zero")}><strong>{n}</strong> {label}</span>;
const Row = ({ k, tag, main, sub }: { k: string; tag: string; main: string; sub: string }) => (
  <li className={"drow " + k}><span className="dtag">{tag}</span><code className="dmain">{main}</code><span className="muted small dsub">{sub}</span></li>
);
