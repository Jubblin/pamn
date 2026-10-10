import { useMemo } from "react";
import type { Host } from "../nmap";
import { buildTopology } from "./model";

const COL = 190, ROW = 54, PAD = 24, W = 150, H = 38;

export default function Topology({ hosts, onPick }: { hosts: Host[]; onPick: (addr: string) => void }) {
  const t = useMemo(() => buildTopology(hosts), [hosts]);
  if (!t.hasTrace) {
    return <p className="empty">No route information in this scan. Turn on <strong>Trace the route</strong> under Fine-tune options and scan again to see how devices connect.</p>;
  }
  const byId = new Map(t.nodes.map((n) => [n.id, n]));
  const x = (d: number) => PAD + d * COL, y = (r: number) => PAD + r * ROW;
  const height = Math.max(...t.nodes.map((n) => y(n.y))) + H + PAD;
  return (
    <div className="topo-scroll">
      <svg width={x(t.maxDepth) + W + PAD} height={height} role="img" aria-label="Network route map">
        {t.nodes.filter((n) => n.parent).map((n) => {
          const p = byId.get(n.parent!)!;
          const x1 = x(p.depth) + W, y1 = y(p.y) + H / 2, x2 = x(n.depth), y2 = y(n.y) + H / 2, mx = (x1 + x2) / 2;
          return <path key={n.id} className={"edge" + (n.kind === "unknown" ? " dashed" : "")} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} />;
        })}
        {t.nodes.map((n) => (
          <g key={n.id} className={"node " + n.kind} transform={`translate(${x(n.depth)},${y(n.y)})`}
            tabIndex={n.kind === "host" ? 0 : undefined} role={n.kind === "host" ? "button" : undefined}
            onClick={() => n.kind === "host" && onPick(n.id)} onKeyDown={(e) => n.kind === "host" && e.key === "Enter" && onPick(n.id)}>
            <title>{n.sub ? `${n.label} (${n.sub})` : n.label}</title>
            <rect width={W} height={H} rx={9} />
            <text x={10} y={n.sub ? 16 : 24} className="n-main">{clip(n.label)}</text>
            {n.sub && <text x={10} y={31} className="n-sub">{clip(n.sub)}</text>}
          </g>
        ))}
      </svg>
      <div className="legend"><span><i className="sw you" />This computer</span><span><i className="sw hop" />Router / hop</span><span><i className="sw host" />Device</span></div>
    </div>
  );
}
const clip = (s: string) => (s.length > 20 ? s.slice(0, 19) + "…" : s);
