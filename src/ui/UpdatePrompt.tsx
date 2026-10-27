import { useState } from "react";
import type { Update } from "./bridge";

export default function UpdatePrompt({ update, onLater }: { update: Update; onLater: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const install = () => { setBusy(true); setErr(""); update.install().catch(() => { setBusy(false); setErr("The update could not be installed. Try again later."); }); };
  return (
    <div className="banner info" role="status">
      <div>
        <strong>Pamn {update.version} is available.</strong>
        {err && <p>{err}</p>}
      </div>
      <span>
        <button className="btn primary" disabled={busy} onClick={install}>{busy ? "Installing…" : "Install and relaunch"}</button>{" "}
        <button className="link" disabled={busy} onClick={onLater}>Later</button>
      </span>
    </div>
  );
}
