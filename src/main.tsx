import React from "react";
import ReactDOM from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type NmapInfo = { path: string; version: string; source: string } | null;

function App() {
  const [nmap, setNmap] = React.useState<NmapInfo | undefined>(undefined);
  const [log, setLog] = React.useState<string[]>([]);
  const [scanId, setScanId] = React.useState<number | null>(null);

  React.useEffect(() => {
    invoke<NmapInfo>("detect_nmap").then(setNmap);
    const subs = [
      listen<{ id: number; line: string }>("scan-output", (e) =>
        setLog((l) => [...l, e.payload.line]),
      ),
      listen<{ id: number; code: number | null; xml: string }>("scan-done", (e) => {
        setLog((l) => [...l, `done (exit ${e.payload.code}), xml ${e.payload.xml.length} bytes`]);
        setScanId(null);
      }),
    ];
    return () => subs.forEach((s) => s.then((f) => f()));
  }, []);

  const start = async () => {
    setLog([]);
    setScanId(await invoke<number>("start_scan", { args: ["-T4", "--stats-every", "1s", "127.0.0.1"] }));
  };

  return (
    <main style={{ fontFamily: "sans-serif", padding: 16 }}>
      <h1>Small Desktop</h1>
      <p>
        {nmap === undefined
          ? "Detecting nmap…"
          : nmap
            ? `nmap ${nmap.version} (${nmap.source}: ${nmap.path})`
            : "nmap not found"}
      </p>
      <button onClick={start} disabled={!nmap || scanId !== null}>Scan 127.0.0.1</button>
      <button onClick={() => invoke("cancel_scan", { id: scanId })} disabled={scanId === null}>Cancel</button>
      <pre>{log.join("\n")}</pre>
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
