import { useEffect, useState } from "react";

/** useState persisted to localStorage. */
export function useStored<T>(key: string, init: T) {
  const [v, set] = useState<T>(() => {
    try { const s = localStorage.getItem(key); return s ? (JSON.parse(s) as T) : init; } catch { return init; }
  });
  useEffect(() => { try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* storage unavailable */ } }, [key, v]);
  return [v, set] as const;
}

export interface HistoryItem { id: string; cmd: string; at: number; status: "done" | "error" | "cancelled"; summary: string }
export interface Profile { id: string; name: string; flags: string }
