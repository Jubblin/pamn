import { useEffect, useRef } from "react";
import notices from "../../THIRD_PARTY_NOTICES.md?raw";
import pkg from "../../package.json";
import type { NmapInfo } from "./bridge";

export default function About({ nmap, welcome, onClose }: { nmap: NmapInfo | undefined; welcome: boolean; onClose: () => void }) {
  const prev = useRef(document.activeElement as HTMLElement | null);
  const close = () => { onClose(); prev.current?.focus(); };
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); close(); } };
    window.addEventListener("keydown", esc, true);
    return () => window.removeEventListener("keydown", esc, true);
  });
  return (
    <div className="palette-bg" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div className="palette about" role="dialog" aria-modal="true" aria-labelledby="about-h">
        <h2 id="about-h">{welcome ? "Welcome to Pamn" : "About Pamn"}</h2>
        <p>{welcome ? "A friendly, free way to see what's on your network." : `Version ${pkg.version} · MIT licence`}</p>
        {welcome && <p>To start: type a website or network address (like <code>192.168.1.0/24</code>) and press <strong>Scan</strong>. Press <kbd>Ctrl/⌘ K</kbd> any time for commands.</p>}
        <button className="btn primary" autoFocus onClick={close}>{welcome ? "Got it" : "Close"}</button>
        <h3>Scanner</h3>
        <p className="muted small">{nmap ? <>{nmap.version}<br /><code>{nmap.path}</code></> : nmap === null ? "nmap was not found." : "Looking for nmap…"}</p>
        <h3>Licences</h3>
        <p className="muted small">Pamn is free and open source under the MIT licence.</p>
        <pre className="notices" tabIndex={0} aria-label="Third-party notices">{notices}</pre>
      </div>
    </div>
  );
}
