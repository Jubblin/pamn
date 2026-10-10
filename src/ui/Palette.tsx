import { useEffect, useRef, useState } from "react";

export interface PaletteItem { id: string; label: string; hint?: string; run: () => void }

export default function Palette({ items, onClose }: { items: PaletteItem[]; onClose: () => void }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const prev = useRef(document.activeElement as HTMLElement | null);
  const shown = items.filter((i) => i.label.toLowerCase().includes(q.trim().toLowerCase()));
  const at = Math.min(sel, shown.length - 1);
  const close = () => { onClose(); prev.current?.focus(); };
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); close(); } };
    window.addEventListener("keydown", esc, true);
    return () => window.removeEventListener("keydown", esc, true);
  });
  const go = (i?: PaletteItem) => { if (!i) return; close(); i.run(); };
  const key = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel(shown.length ? (at + 1) % shown.length : 0); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel(shown.length ? (at - 1 + shown.length) % shown.length : 0); }
    else if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); go(shown[at]); }
  };
  return (
    <div className="palette-bg" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette" onKeyDown={key}>
        <input className="input" autoFocus role="combobox" aria-expanded aria-controls="pal-list" aria-autocomplete="list" aria-label="Type a command"
          aria-activedescendant={shown[at] ? "pal-" + shown[at].id : undefined} placeholder="Type a command…" value={q} onChange={(e) => { setQ(e.target.value); setSel(0); }} />
        {shown.length === 0 ? <p className="empty" role="status">No matching commands.</p> : (
          <ul id="pal-list" role="listbox" aria-label="Commands">
            {shown.map((i, n) => (
              <li key={i.id} id={"pal-" + i.id} role="option" aria-selected={n === at} onMouseMove={() => setSel(n)} onClick={() => go(i)}>
                <span>{i.label}</span>{i.hint && <span className="muted small">{i.hint}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
