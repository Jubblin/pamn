import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { buildCommand, parseCommand, parseNmapXml, tokenize, type NmapOptions, type NmapResult } from "./nmap";
import { cancelScan, detectNmap, onScanEvents, startScan, type DoneEvent, type NmapInfo, type OutputEvent } from "./ui/bridge";
import { PRESETS, SCAN_TYPES, TIMINGS, applyFlags, invalidTarget, optionsKey, presetKey } from "./ui/presets";
import { useStored, type HistoryItem, type Profile } from "./ui/store";
import Results from "./results/Results";
import { parseLive } from "./results/model";

type Status = "idle" | "running" | "done" | "error" | "cancelled";
interface Tab {
  key: string; cmd: string; targetText: string; status: Status;
  scanId?: number; log: string[]; pct?: number; remaining?: string; startedAt?: number;
  result?: NmapResult; xml?: string; message?: string; needsPrivs?: boolean; cancelling?: boolean;
}

let keySeq = 0;
const newTab = (cmd = "nmap -T4 -F", targetText = ""): Tab => ({ key: `t${++keySeq}`, cmd, targetText, status: "idle", log: [] });
const PROGRESS = /About\s+([\d.]+)% done(?:; ETC: [^(]*\((\S+) remaining\))?/;
const PRIV = /root privileges|requires root|Operation not permitted|permission denied|administrator/i;

const tabTitle = (t: Tab) => t.targetText.trim() || "New scan";
const dedupeTargets = (o: NmapOptions, text: string): NmapOptions => ({ ...o, targets: tokenize(text) });

function summarize(r?: NmapResult): string {
  if (!r) return "";
  const up = r.hosts.filter((h) => h.status === "up");
  const open = up.reduce((n, h) => n + h.ports.filter((p) => p.state === "open").length, 0);
  return `${up.length} host${up.length === 1 ? "" : "s"} up · ${open} open port${open === 1 ? "" : "s"}`;
}

export default function App() {
  const [nmap, setNmap] = useState<NmapInfo | undefined>(undefined);
  const [tabs, setTabs] = useState<Tab[]>(() => [newTab()]);
  const [active, setActive] = useState(tabs[0].key);
  const [history, setHistory] = useStored<HistoryItem[]>("sd.history", []);
  const [profiles, setProfiles] = useStored<Profile[]>("sd.profiles", []);
  const [theme, setTheme] = useStored<"system" | "light" | "dark">("sd.theme", "system");
  const [showOptions, setShowOptions] = useState(false);
  const [showLog, setShowLog] = useState(true);
  const [naming, setNaming] = useState<string | null>(null);

  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const pending = useRef(new Map<number, Array<(t: Tab) => Tab>>());

  const tab = tabs.find((t) => t.key === active) ?? tabs[0];
  const patch = useCallback((key: string, f: (t: Tab) => Tab) => setTabs((ts) => ts.map((t) => (t.key === key ? f(t) : t))), []);

  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => { detectNmap().then(setNmap).catch(() => setNmap(null)); }, []);

  // Route scan events to their tab. Events can arrive before start_scan has returned the id, so buffer those.
  const route = useCallback((id: number, f: (t: Tab) => Tab) => {
    const t = tabsRef.current.find((x) => x.scanId === id);
    if (t) patch(t.key, f);
    else pending.current.set(id, [...(pending.current.get(id) ?? []), f]);
  }, [patch]);

  const saveHistory = useCallback((t: Tab, status: HistoryItem["status"], result?: NmapResult) => {
    const item: HistoryItem = { id: `${Date.now()}-${t.key}`, cmd: t.cmd, at: Date.now(), status, summary: status === "done" ? summarize(result) : status === "cancelled" ? "Cancelled" : "Failed" };
    setHistory((h) => [item, ...h].slice(0, 50));
  }, [setHistory]);

  useEffect(() => onScanEvents(
    (e: OutputEvent) => route(e.id, (t) => {
      const m = PROGRESS.exec(e.line);
      return { ...t, log: [...t.log, e.line].slice(-2000), pct: m ? parseFloat(m[1]) : t.pct, remaining: m ? (m[2] ?? t.remaining) : t.remaining };
    }),
    (e: DoneEvent) => route(e.id, (t) => {
      let result: NmapResult | undefined;
      try { result = e.xml ? parseNmapXml(e.xml) : undefined; } catch { /* no usable XML */ }
      const needsPrivs = e.code !== 0 && !t.cancelling && t.log.some((l) => PRIV.test(l));
      const status: Status = t.cancelling || e.code === null ? "cancelled" : e.code === 0 ? "done" : "error";
      return { ...t, status, result, xml: e.xml || undefined, needsPrivs, pct: status === "done" ? 100 : t.pct, scanId: undefined,
        message: status === "error" ? (needsPrivs ? undefined : t.log.filter((l) => l.trim()).slice(-1)[0] ?? "The scan failed.") : undefined };
    }),
  ), [route, saveHistory]);

  const prevStatus = useRef(new Map<string, Status>());
  useEffect(() => {
    for (const t of tabs) {
      const was = prevStatus.current.get(t.key);
      prevStatus.current.set(t.key, t.status);
      if (was === "running" && t.status !== "running" && !t.needsPrivs) saveHistory(t, t.status === "done" ? "done" : t.status === "cancelled" ? "cancelled" : "error", t.result);
    }
  }, [tabs, saveHistory]);

  const opts = useMemo(() => parseCommand(tab.cmd), [tab.cmd]);
  const bad = invalidTarget(opts.targets);
  const noTarget = opts.targets.length === 0;
  const running = tab.status === "running";
  const activePreset = PRESETS.find((p) => presetKey(p) === optionsKey(opts))?.id;
  const matchedProfile = profiles.find((p) => optionsKey(parseCommand("nmap " + p.flags)) === optionsKey(opts));

  const setCmd = (cmd: string) => patch(tab.key, (t) => {
    const parsed = parseCommand(cmd).targets;
    const same = tokenize(t.targetText).join(" ") === parsed.join(" ");
    return { ...t, cmd, targetText: same ? t.targetText : parsed.join(" ") };
  });
  const setTarget = (text: string) => patch(tab.key, (t) => ({ ...t, targetText: text, cmd: buildCommand(dedupeTargets(parseCommand(t.cmd), text)) }));
  const setOpts = (f: (o: NmapOptions) => NmapOptions) => patch(tab.key, (t) => ({ ...t, cmd: buildCommand(f(parseCommand(t.cmd))) }));

  const run = async (cmd = tab.cmd) => {
    const key = tab.key;
    const args = tokenize(cmd).slice(1);
    if (!args.includes("--stats-every")) args.push("--stats-every", "1s");
    patch(key, (t) => ({ ...t, status: "running", log: [], pct: undefined, remaining: undefined, result: undefined, xml: undefined, message: undefined, needsPrivs: false, cancelling: false, startedAt: Date.now() }));
    try {
      const id = await startScan(args);
      patch(key, (t) => ({ ...t, scanId: id }));
      tabsRef.current = tabsRef.current.map((t) => (t.key === key ? { ...t, scanId: id } : t));
      const queued = pending.current.get(id);
      pending.current.delete(id);
      queued?.forEach((f) => patch(key, f));
    } catch (err) {
      patch(key, (t) => ({ ...t, status: "error", message: String(err) }));
    }
  };
  const cancel = () => {
    patch(tab.key, (t) => ({ ...t, cancelling: true }));
    if (tab.scanId !== undefined) cancelScan(tab.scanId).catch(() => {});
  };
  const useConnectScan = () => {
    const cmd = buildCommand({ ...opts, scanType: "-sT", os: false });
    patch(tab.key, (t) => ({ ...t, cmd, needsPrivs: false }));
    run(cmd);
  };

  const addTab = (cmd?: string) => {
    const t = newTab(cmd ?? "nmap -T4 -F", cmd ? parseCommand(cmd).targets.join(" ") : "");
    setTabs((ts) => [...ts, t]);
    setActive(t.key);
  };
  const closeTab = (key: string) => {
    const t = tabs.find((x) => x.key === key);
    if (t?.scanId !== undefined) cancelScan(t.scanId).catch(() => {});
    const rest = tabs.filter((x) => x.key !== key);
    if (rest.length === 0) { const n = newTab(); setTabs([n]); setActive(n.key); return; }
    setTabs(rest);
    if (key === active) setActive(rest[Math.max(0, tabs.findIndex((x) => x.key === key) - 1)].key);
  };

  const [openError, setOpenError] = useState("");
  const openFile = async (f?: File) => {
    if (!f) return;
    try {
      const xml = await f.text();
      const result = parseNmapXml(xml);
      const cmd = result.args.startsWith("nmap") ? result.args : "nmap " + result.args;
      const t: Tab = { ...newTab(cmd, parseCommand(cmd).targets.join(" ") || f.name), status: "done", result, xml, pct: 100 };
      setTabs((ts) => [...ts, t]);
      setActive(t.key);
      setOpenError("");
    } catch (err) { setOpenError(`Couldn't open ${f.name}: ${err instanceof Error ? err.message : err}`); }
  };
  const fileInput = useRef<HTMLInputElement>(null);
  const live = useMemo(() => (running ? parseLive(tab.log) : undefined), [running, tab.log]);
  const shown = running ? live : tab.result;
  const others = tabs.filter((t) => t.key !== tab.key && t.result).map((t) => ({ label: `${tabTitle(t)} — ${t.cmd}`, result: t.result! }));

  const saveProfile = (name: string) => {
    const flags = optionsKey(opts).replace(/^nmap\s*/, "");
    setProfiles((p) => [...p, { id: String(Date.now()), name, flags }]);
    setNaming(null);
  };

  const logRef = useRef<HTMLPreElement>(null);
  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [tab.log.length, showLog]);

  const canRun = !!nmap && !running && !noTarget && !bad;
  const hint = !nmap && nmap !== undefined ? "nmap wasn't found" : noTarget ? "Enter a target to scan" : bad ? `"${bad}" doesn't look like a valid target` : "";

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand"><span className="logo" aria-hidden>◎</span> Small Desktop</div>
        <div role="tablist" aria-label="Scans" className="tabs">
          {tabs.map((t) => (
            <div key={t.key} className={"tab" + (t.key === active ? " on" : "")}>
              <button role="tab" aria-selected={t.key === active} className="tab-btn" onClick={() => setActive(t.key)}>
                <span className={"dot " + t.status} aria-hidden />
                <span className="tab-title">{tabTitle(t)}</span>
                {t.status === "running" && t.pct !== undefined && <span className="tab-pct">{Math.round(t.pct)}%</span>}
              </button>
              <button className="icon-btn sm" aria-label={`Close ${tabTitle(t)}`} onClick={() => closeTab(t.key)}>×</button>
            </div>
          ))}
          <button className="icon-btn" aria-label="New scan" title="New scan" onClick={() => addTab()}>＋</button>
        </div>
        <div className="top-right">
          <span className={"chip " + (nmap ? "ok" : nmap === null ? "warn" : "")} title={nmap?.path}>
            {nmap === undefined ? "Looking for nmap…" : nmap ? nmap.version.replace(/^Nmap version /, "nmap ").replace(/ \(.*$/, "") : "nmap not found"}
          </span>
          <button className="btn sm" onClick={() => fileInput.current?.click()} title="Open a saved nmap XML file">Open…</button>
          <input ref={fileInput} type="file" accept=".xml,text/xml" hidden onChange={(e) => { openFile(e.target.files?.[0]); e.target.value = ""; }} />
          <button className="icon-btn" aria-label={`Theme: ${theme}. Click to change`} title={`Theme: ${theme}`}
            onClick={() => setTheme(theme === "system" ? "light" : theme === "light" ? "dark" : "system")}>
            {theme === "dark" ? "☾" : theme === "light" ? "☀" : "◐"}
          </button>
        </div>
      </header>

      <div className="body">
        <aside className="rail" aria-label="Profiles and history">
          <section>
            <h2>My profiles</h2>
            {profiles.length === 0 && <p className="muted small">Set up a scan the way you like, then save it here.</p>}
            <ul className="list">
              {profiles.map((p) => (
                <li key={p.id}>
                  <button className="list-btn" onClick={() => patch(tab.key, (t) => ({ ...t, cmd: applyFlags(t.cmd, p.flags) }))} title={"nmap " + p.flags}>
                    <span>{p.name}</span><code>{p.flags}</code>
                  </button>
                  <button className="icon-btn sm" aria-label={`Delete profile ${p.name}`} onClick={() => setProfiles((ps) => ps.filter((x) => x.id !== p.id))}>×</button>
                </li>
              ))}
            </ul>
          </section>
          <section>
            <div className="h-row"><h2>History</h2>{history.length > 0 && <button className="link" onClick={() => setHistory([])}>Clear</button>}</div>
            {history.length === 0 && <p className="muted small">Finished scans show up here so you can run them again.</p>}
            <ul className="list">
              {history.map((h) => (
                <li key={h.id}>
                  <button className="list-btn" onClick={() => addTab(h.cmd)} title={h.cmd}>
                    <span className="hist-target">{parseCommand(h.cmd).targets.join(" ") || "scan"}</span>
                    <small>{new Date(h.at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })} · {h.summary}</small>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        </aside>

        <main className="main" key={tab.key}>
          {openError && <div className="banner warn" role="alert"><span>{openError}</span><button className="link" onClick={() => setOpenError("")}>Dismiss</button></div>}
          {nmap === null && (
            <div className="banner warn" role="alert">
              <strong>nmap isn't installed.</strong> This app needs nmap to scan. Install it (for example <code>brew install nmap</code>) and reopen the app.
            </div>
          )}

          <section className="card">
            <label htmlFor="target" className="label">What do you want to scan?</label>
            <div className="target-row">
              <input id="target" className={"input big" + (bad ? " invalid" : "")} value={tab.targetText} placeholder="scanme.nmap.org, 192.168.1.0/24 or 10.0.0.1-50"
                autoFocus spellCheck={false} autoComplete="off" aria-invalid={!!bad} aria-describedby="target-help" disabled={running}
                onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === "Enter" && canRun && run()} />
              {running
                ? <button className="btn danger" onClick={cancel} disabled={tab.cancelling}>{tab.cancelling ? "Stopping…" : "Cancel"}</button>
                : <button className="btn primary" onClick={() => run()} disabled={!canRun} title={hint}>Scan</button>}
            </div>
            <p id="target-help" className={"help" + (bad ? " err" : "")}>
              {bad ? hint : "A website, an IP address, a whole network (192.168.1.0/24) or a range. Separate several with spaces."}
              {!bad && hint && !noTarget && <span> {hint}.</span>}
            </p>
            <p className="warn-note">Only scan networks you own or have permission to test.</p>
          </section>

          {tab.needsPrivs && (
            <div className="banner info" role="alert">
              <div>
                <strong>This scan needs administrator rights.</strong>
                <p>Some scan types (like SYN, UDP and OS detection) talk to the network at a low level, which your account isn't allowed to do. You can run a slightly less detailed scan that works without them.</p>
              </div>
              <button className="btn primary" onClick={useConnectScan}>Scan without admin rights</button>
            </div>
          )}
          {tab.status === "error" && !tab.needsPrivs && <div className="banner warn" role="alert"><strong>The scan didn't finish.</strong> {tab.message}</div>}

          {(tab.status !== "idle") && (
            <section className="card" aria-live="polite">
              <div className="h-row">
                <h2>{running ? (tab.cancelling ? "Stopping…" : "Scanning…") : tab.status === "done" ? "Scan complete" : tab.status === "cancelled" ? "Scan cancelled" : "Stopped"}</h2>
                {running && tab.remaining && <span className="muted small">about {tab.remaining} left</span>}
                {tab.status === "done" && <span className="muted small">{summarize(tab.result)}</span>}
              </div>
              <div className={"bar" + (running && tab.pct === undefined ? " indet" : "")} role="progressbar" aria-label="Scan progress"
                aria-valuemin={0} aria-valuemax={100} aria-valuenow={tab.pct === undefined ? undefined : Math.round(tab.pct)}>
                <div className={"fill " + tab.status} style={{ width: `${tab.status === "done" ? 100 : tab.pct ?? 0}%` }} />
              </div>
              {running && <p className="muted small">{tab.pct === undefined ? "Starting up — progress appears once nmap has something to estimate." : `${Math.round(tab.pct)}% done`}</p>}
              {(running || tab.log.length > 0) && <div className="drawer">
                <button className="link" aria-expanded={showLog} onClick={() => setShowLog(!showLog)}>{showLog ? "▾" : "▸"} Live output</button>
                {showLog && <pre ref={logRef} className="log" tabIndex={0} aria-label="nmap output">{tab.log.join("\n") || "Waiting for output…"}</pre>}
              </div>}
            </section>
          )}
          {shown && (shown.hosts.length > 0 || tab.status === "done") && <Results result={shown} live={running} xml={tab.xml} name={tabTitle(tab)} others={others} />}

          <section className="card" aria-labelledby="presets-h">
            <div className="h-row"><h2 id="presets-h">Type of scan</h2></div>
            <div className="presets" role="radiogroup" aria-labelledby="presets-h">
              {PRESETS.map((p) => (
                <button key={p.id} role="radio" aria-checked={activePreset === p.id} className={"preset" + (activePreset === p.id ? " on" : "")} disabled={running}
                  onClick={() => patch(tab.key, (t) => ({ ...t, cmd: applyFlags(t.cmd, p.flags) }))}>
                  <span className="preset-ico" aria-hidden>{p.icon}</span>
                  <span className="preset-name">{p.name}</span>
                  <span className="preset-blurb">{p.blurb}</span>
                </button>
              ))}
            </div>
            <div className="h-row below">
              <button className="link" aria-expanded={showOptions} onClick={() => setShowOptions(!showOptions)}>{showOptions ? "▾" : "▸"} Fine-tune options</button>
              {!activePreset && !matchedProfile && <span className="muted small">Custom settings</span>}
              {matchedProfile && <span className="muted small">Profile: {matchedProfile.name}</span>}
              {!matchedProfile && (naming === null
                ? <button className="link" onClick={() => setNaming("")}>Save as profile…</button>
                : <form className="inline-form" onSubmit={(e) => { e.preventDefault(); if (naming.trim()) saveProfile(naming.trim()); }}>
                    <input className="input sm" aria-label="Profile name" placeholder="Profile name" value={naming} autoFocus onChange={(e) => setNaming(e.target.value)} onKeyDown={(e) => e.key === "Escape" && setNaming(null)} />
                    <button className="btn sm" type="submit" disabled={!naming.trim()}>Save</button>
                  </form>)}
            </div>
            {showOptions && <Options o={opts} set={setOpts} disabled={running} />}
          </section>

          <section className="card">
            <label htmlFor="cmd" className="label">Command <span className="muted">— edit it directly if you like; the options above follow along</span></label>
            <div className="cmd-wrap">
              <input id="cmd" className="input mono" value={tab.cmd} spellCheck={false} autoComplete="off" autoCapitalize="off" disabled={running} onChange={(e) => setCmd(e.target.value)} />
              <button className="btn sm" onClick={() => navigator.clipboard?.writeText(tab.cmd)} aria-label="Copy command">Copy</button>
            </div>
            {opts.extra.length > 0 && <p className="help">Kept as typed: <code>{opts.extra.join(" ")}</code></p>}
          </section>

        </main>
      </div>
    </div>
  );
}

function Options({ o, set, disabled }: { o: NmapOptions; set: (f: (o: NmapOptions) => NmapOptions) => void; disabled: boolean }) {
  const toggles: Array<[keyof NmapOptions, string, string]> = [
    ["serviceVersion", "Detect software versions", "Finds out what is running on open ports."],
    ["os", "Detect operating system", "Needs administrator rights."],
    ["defaultScripts", "Run safe default checks", "Extra probes from nmap's default script set."],
    ["traceroute", "Trace the route", "Shows the hops to each device."],
    ["skipPing", "Treat every device as online", "Useful when devices ignore ping."],
    ["noDns", "Skip name lookups", "Faster; shows IP addresses only."],
  ];
  return (
    <div className="options">
      <div className="toggles">
        {toggles.map(([k, label, desc]) => (
          <label key={k} className="toggle">
            <input type="checkbox" checked={!!o[k]} disabled={disabled} onChange={(e) => set((x) => ({ ...x, [k]: e.target.checked || undefined }))} />
            <span><span className="t-label">{label}</span><span className="t-desc">{desc}</span></span>
          </label>
        ))}
      </div>
      <div className="fields">
        <label className="field"><span>Ports</span>
          <input className="input sm" value={o.ports ?? ""} placeholder="e.g. 22,80,443 or 1-1024" disabled={disabled} onChange={(e) => set((x) => ({ ...x, ports: e.target.value || undefined, fast: e.target.value ? undefined : x.fast }))} /></label>
        <label className="field"><span>Speed</span>
          <select className="input sm" value={o.timing ?? ""} disabled={disabled} onChange={(e) => set((x) => ({ ...x, timing: e.target.value === "" ? undefined : +e.target.value }))}>
            {TIMINGS.map((t) => <option key={t.label} value={t.v ?? ""}>{t.label}</option>)}
          </select></label>
        <label className="field"><span>Method</span>
          <select className="input sm" value={o.scanType ?? ""} disabled={disabled} onChange={(e) => set((x) => ({ ...x, scanType: e.target.value || undefined }))}>
            {SCAN_TYPES.map((t) => <option key={t.v} value={t.v}>{t.label}</option>)}
          </select></label>
      </div>
    </div>
  );
}
