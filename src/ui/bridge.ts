// Thin wrapper over Tauri. In a plain browser (vite dev) a fake nmap is used so the UI can be developed and screenshotted.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type NmapInfo = { path: string; version: string; source: string } | null;
export type OutputEvent = { id: number; stream?: string; line: string };
export type DoneEvent = { id: number; code: number | null; xml: string };

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const mock = (() => {
  const subs = { out: new Set<(e: OutputEvent) => void>(), done: new Set<(e: DoneEvent) => void>() };
  const timers = new Map<number, number>();
  let next = 0;
  const xml = `<nmaprun args="nmap" version="7.95"><host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><hostnames><hostname name="router.lan"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host><host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports></host><runstats><finished elapsed="9.1" exit="success"/><hosts up="2" down="254" total="256"/></runstats></nmaprun>`;
  return {
    start(args: string[]) {
      if (args.includes("-sS") || args.includes("-O")) {
        const id = ++next;
        setTimeout(() => {
          subs.out.forEach((f) => f({ id, line: "You requested a scan type which requires root privileges.", stream: "stderr" }));
          subs.out.forEach((f) => f({ id, line: "QUITTING!", stream: "stderr" }));
          subs.done.forEach((f) => f({ id, code: 1, xml: "" }));
        }, 400);
        return id;
      }
      const id = ++next;
      let pct = 0;
      subs.out.forEach((f) => f({ id, line: "Starting Nmap 7.95 ( https://nmap.org )" }));
      timers.set(id, window.setInterval(() => {
        pct += 8;
        if (pct >= 100) {
          clearInterval(timers.get(id));
          subs.out.forEach((f) => f({ id, line: "Nmap done: 256 IP addresses (2 hosts up) scanned in 9.10 seconds" }));
          subs.done.forEach((f) => f({ id, code: 0, xml }));
        } else {
          subs.out.forEach((f) => f({ id, line: `Connect Scan Timing: About ${pct}.00% done; ETC: 12:00 (0:00:${String(Math.round((100 - pct) / 10)).padStart(2, "0")} remaining)` }));
        }
      }, 700));
      return id;
    },
    cancel(id: number) {
      clearInterval(timers.get(id));
      subs.done.forEach((f) => f({ id, code: null, xml: "" }));
    },
    subs,
  };
})();

export const npcapMissing = (): Promise<boolean> => (inTauri ? invoke<boolean>("npcap_missing") : Promise.resolve(false));
export const vcruntimeMissing = (): Promise<boolean> => (inTauri ? invoke<boolean>("vcruntime_missing") : Promise.resolve(false));
export const openNpcapPage = (): Promise<void> => (inTauri ? invoke<void>("open_npcap_page") : Promise.resolve());
export const detectNmap = (): Promise<NmapInfo> =>
  inTauri ? invoke<NmapInfo>("detect_nmap") : Promise.resolve({ path: "/usr/local/bin/nmap", version: "Nmap version 7.95 (demo)", source: "demo" });

export const startScan = (args: string[]): Promise<number> =>
  inTauri ? invoke<number>("start_scan", { args }) : Promise.resolve(mock.start(args));

export const cancelScan = (id: number): Promise<void> =>
  inTauri ? invoke<void>("cancel_scan", { id }) : Promise.resolve(mock.cancel(id));

/** Returns an unsubscribe function. */
export function onScanEvents(onOut: (e: OutputEvent) => void, onDone: (e: DoneEvent) => void): () => void {
  if (!inTauri) {
    mock.subs.out.add(onOut);
    mock.subs.done.add(onDone);
    return () => { mock.subs.out.delete(onOut); mock.subs.done.delete(onDone); };
  }
  const subs = [listen<OutputEvent>("scan-output", (e) => onOut(e.payload)), listen<DoneEvent>("scan-done", (e) => onDone(e.payload))];
  return () => subs.forEach((s) => s.then((f) => f()));
}
