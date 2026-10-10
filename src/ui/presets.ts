import { buildCommand, parseCommand, type NmapOptions } from "../nmap";

export interface Preset { id: string; name: string; blurb: string; flags: string; icon: string }

export const PRESETS: Preset[] = [
  { id: "quick", name: "Quick scan", blurb: "Checks the most common ports. Fast and a good first look.", flags: "-T4 -F", icon: "⚡" },
  { id: "ping", name: "Who's online?", blurb: "Only finds which devices respond. No port checks.", flags: "-sn", icon: "📡" },
  { id: "services", name: "Services & versions", blurb: "Finds open ports and what software is listening.", flags: "-T4 -sV", icon: "🔎" },
  { id: "allports", name: "Every port", blurb: "Checks all 65,535 ports. Thorough but slower.", flags: "-T4 -p 1-65535", icon: "🧭" },
  { id: "os", name: "Identify devices", blurb: "Guesses the operating system. Needs administrator rights.", flags: "-T4 -O -sV", icon: "🖥" },
  { id: "intense", name: "Intense scan", blurb: "Ports, versions, OS, scripts and route. The works.", flags: "-T4 -A -v", icon: "🔬" },
];

/** Options with targets stripped, as a canonical string for comparing against presets/profiles. */
export const optionsKey = (o: NmapOptions) => buildCommand({ ...o, targets: [] });
export const presetKey = (p: Preset) => optionsKey(parseCommand("nmap " + p.flags));

/** Replace everything but the targets with the given flags. */
export function applyFlags(cmd: string, flags: string): string {
  const targets = parseCommand(cmd).targets;
  return buildCommand({ ...parseCommand("nmap " + flags), targets });
}

export const TIMINGS = [
  { v: undefined, label: "Default" },
  { v: 2, label: "Polite (gentle on the network)" },
  { v: 3, label: "Normal" },
  { v: 4, label: "Fast" },
  { v: 5, label: "Insane (may miss results)" },
] as const;

export const SCAN_TYPES = [
  { v: "", label: "Automatic" },
  { v: "-sT", label: "Connect (no admin needed)" },
  { v: "-sS", label: "SYN stealth (needs admin)" },
  { v: "-sU", label: "UDP (needs admin, slow)" },
  { v: "-sn", label: "Ping only" },
];

const HOST = /^(?=.{1,253}(\/\d{1,2})?$)[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*(\/\d{1,2})?$/i;
const V4 = /^[\d*,-]+(\.[\d*,-]+){3}(\/(\d|[12]\d|3[0-2]))?$/;
const V6 = /^[0-9a-f]*:[0-9a-f:.]*:[0-9a-f:.]*(%\w+)?(\/\d{1,3})?$/i;

/** Returns the first invalid target, or null. Accepts hostnames, IPs, CIDR, ranges (10.0.0.1-20, 10.0.*.*). */
export const invalidTarget = (targets: string[]): string | null =>
  targets.find((t) => !(V4.test(t) || V6.test(t) || (HOST.test(t) && !/^[\d.]+$/.test(t)))) ?? null;
