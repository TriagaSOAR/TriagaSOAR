import { useEffect, useState, useRef } from "react";

interface Case {
  report_id: string;
  created_at: string;
  title: string;
  severity: string;
  alert_type: string;
  confidence: number;
  kill_chain: string;
  summary: string;
}

interface Props {
  apiUrl: string;
}

const SEVERITY_ROWS = ["critical", "high", "medium", "low"];

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ff4d6a",
  high: "#ff8c42",
  medium: "#ffd166",
  low: "#06d6a0",
};

type ViewMode = "swimlane" | "heatmap";

export default function CaseTimeline({ apiUrl }: Props) {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<ViewMode>("swimlane");
  const [tooltip, setTooltip] = useState<{ c: Case; x: number; y: number } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    fetch(`${apiUrl}/cases`)
      .then((r) => r.json())
      .then((data) => {
        const sorted = [...data].sort(
          (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
        );
        setCases(sorted);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
      Loading timeline...
    </div>
  );

  if (cases.length === 0) return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <Header view={view} setView={setView} count={0} />
      <div className="card" style={{ color: "var(--text-muted)", fontSize: 13 }}>No cases yet.</div>
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <Header view={view} setView={setView} count={cases.length} />

      {view === "swimlane" ? (
        <SwimlaneView cases={cases} tooltip={tooltip} setTooltip={setTooltip} svgRef={svgRef} />
      ) : (
        <HeatmapView cases={cases} />
      )}

      {tooltip && (
        <div style={{
          position: "fixed",
          left: Math.min(tooltip.x + 12, window.innerWidth - 320),
          top: Math.min(tooltip.y + 12, window.innerHeight - 200),
          zIndex: 1000,
          background: "var(--bg-card)",
          border: `1px solid ${SEVERITY_COLOR[tooltip.c.severity] ?? "var(--border)"}`,
          borderRadius: 8,
          padding: "12px 16px",
          maxWidth: 300,
          pointerEvents: "none",
          boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span className={`badge badge-${tooltip.c.severity}`}>{tooltip.c.severity}</span>
            <span style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--text-muted)" }}>
              {Math.round(tooltip.c.confidence * 100)}%
            </span>
          </div>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 4 }}>
            {tooltip.c.title}
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 6 }}>
            {new Date(tooltip.c.created_at).toLocaleString()}
          </div>
          {tooltip.c.kill_chain && (
            <div style={{ fontSize: 11, color: "var(--accent)", fontFamily: "Geist Mono" }}>
              {tooltip.c.kill_chain}
            </div>
          )}
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--accent)", fontFamily: "Geist Mono" }}>
            click to open report
          </div>
        </div>
      )}
    </div>
  );
}

function Header({ view, setView, count }: { view: ViewMode; setView: (v: ViewMode) => void; count: number }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
          Case Timeline
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          {count} incidents · attack patterns and temporal clustering
        </p>
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        {(["swimlane", "heatmap"] as ViewMode[]).map((v) => (
          <button
            key={v}
            onClick={() => setView(v)}
            style={{
              padding: "6px 14px", borderRadius: 4,
              border: `1px solid ${view === v ? "var(--accent)" : "var(--border)"}`,
              background: view === v ? "var(--accent-glow)" : "transparent",
              color: view === v ? "var(--accent)" : "var(--text-muted)",
              fontSize: 12, fontFamily: "Geist Mono",
              cursor: "pointer", textTransform: "uppercase",
              transition: "all 0.15s",
            }}
          >
            {v}
          </button>
        ))}
      </div>
    </div>
  );
}

function SwimlaneView({ cases, tooltip, setTooltip, svgRef }: {
  cases: Case[];
  tooltip: any;
  setTooltip: (t: any) => void;
  svgRef: React.RefObject<SVGSVGElement | null>;
}) {
  const WIDTH = 900;
  const ROW_HEIGHT = 80;
  const PADDING_LEFT = 90;
  const PADDING_RIGHT = 24;
  const PADDING_TOP = 32;
  const DOT_R = 8;

  const timestamps = cases.map((c) => new Date(c.created_at).getTime());
  const minT = Math.min(...timestamps);
  const maxT = Math.max(...timestamps);
  const range = maxT - minT || 1;

  const plotW = WIDTH - PADDING_LEFT - PADDING_RIGHT;

  function xPos(ts: number) {
    return PADDING_LEFT + ((ts - minT) / range) * plotW;
  }

  function yPos(severity: string) {
    const idx = SEVERITY_ROWS.indexOf(severity);
    return PADDING_TOP + (idx === -1 ? 0 : idx) * ROW_HEIGHT + ROW_HEIGHT / 2;
  }

  // Group cases by attacker IP for arc lines
  // We don't have IP directly but can group by report similarity
  // Group cases with same severity close in time as "clusters"
  const clusters: Case[][] = [];
  const used = new Set<string>();
  for (const c of cases) {
    if (used.has(c.report_id)) continue;
    const cluster = [c];
    used.add(c.report_id);
    const ct = new Date(c.created_at).getTime();
    for (const d of cases) {
      if (used.has(d.report_id)) continue;
      const dt = new Date(d.created_at).getTime();
      if (Math.abs(dt - ct) < 5 * 60 * 1000) { // within 5 minutes
        cluster.push(d);
        used.add(d.report_id);
      }
    }
    clusters.push(cluster);
  }

  // Group cases by matching kill_chain (same attacker pattern) for arc lines
  const arcGroups: Case[][] = [];
  const arcUsed = new Set<string>();
  for (const c of cases) {
    if (arcUsed.has(c.report_id) || !c.kill_chain) continue;
    const group = cases.filter(
      (d) => d.kill_chain === c.kill_chain && d.report_id !== c.report_id
    );
    if (group.length > 0) {
      const fullGroup = [c, ...group];
      fullGroup.forEach((d) => arcUsed.add(d.report_id));
      arcGroups.push(fullGroup);
    }
  }

  const HEIGHT = PADDING_TOP + SEVERITY_ROWS.length * ROW_HEIGHT + 40;

  // Time labels
  const timeLabels: { label: string; x: number }[] = [];
  if (cases.length > 1) {
    for (let i = 0; i <= 4; i++) {
      const t = minT + (range * i) / 4;
      timeLabels.push({
        label: new Date(t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
        x: xPos(t),
      });
    }
  }

  return (
    <div className="card" style={{ overflowX: "auto" }}>
      <svg
        ref={svgRef}
        width={WIDTH}
        height={HEIGHT}
        style={{ display: "block" }}
        onMouseLeave={() => setTooltip(null)}
      >
        {/* Row backgrounds */}
        {SEVERITY_ROWS.map((sev, i) => (
          <g key={sev}>
            <rect
              x={0} y={PADDING_TOP + i * ROW_HEIGHT}
              width={WIDTH} height={ROW_HEIGHT}
              fill={i % 2 === 0 ? "rgba(255,255,255,0.02)" : "transparent"}
            />
            <text
              x={PADDING_LEFT - 10} y={PADDING_TOP + i * ROW_HEIGHT + ROW_HEIGHT / 2 + 4}
              textAnchor="end"
              fill={SEVERITY_COLOR[sev]}
              fontSize={11}
              fontFamily="Geist Mono"
              fontWeight={600}
              style={{ textTransform: "uppercase" }}
            >
              {sev}
            </text>
            <line
              x1={PADDING_LEFT} y1={PADDING_TOP + i * ROW_HEIGHT + ROW_HEIGHT / 2}
              x2={WIDTH - PADDING_RIGHT} y2={PADDING_TOP + i * ROW_HEIGHT + ROW_HEIGHT / 2}
              stroke="rgba(255,255,255,0.05)" strokeWidth={1}
            />
          </g>
        ))}

        {/* Arc lines connecting same-pattern cases */}
        {arcGroups.map((group, gi) => {
          const sorted = [...group].sort(
            (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
          );
          return sorted.slice(0, -1).map((c, i) => {
            const next = sorted[i + 1];
            const x1 = xPos(new Date(c.created_at).getTime());
            const y1 = yPos(c.severity);
            const x2 = xPos(new Date(next.created_at).getTime());
            const y2 = yPos(next.severity);
            const mx = (x1 + x2) / 2;
            const my = Math.min(y1, y2) - 20;
            return (
              <path
                key={`arc-${gi}-${i}`}
                d={`M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`}
                fill="none"
                stroke={SEVERITY_COLOR[c.severity] ?? "#888"}
                strokeWidth={1.5}
                strokeDasharray="4 3"
                opacity={0.4}
              />
            );
          });
        })}

        {/* Cluster halos */}
        {clusters.filter((cl) => cl.length > 1).map((cluster, ci) => {
          const xs = cluster.map((c) => xPos(new Date(c.created_at).getTime()));
          const ys = cluster.map((c) => yPos(c.severity));
          const cx = xs.reduce((a, b) => a + b, 0) / xs.length;
          const cy = ys.reduce((a, b) => a + b, 0) / ys.length;
          const r = Math.max(
            ...cluster.map((c) => {
              const dx = xPos(new Date(c.created_at).getTime()) - cx;
              const dy = yPos(c.severity) - cy;
              return Math.sqrt(dx * dx + dy * dy);
            })
          ) + DOT_R + 6;
          return (
            <ellipse
              key={`cluster-${ci}`}
              cx={cx} cy={cy}
              rx={Math.max(r, 20)} ry={Math.max(r * 0.6, 16)}
              fill="rgba(123,97,255,0.06)"
              stroke="rgba(123,97,255,0.2)"
              strokeWidth={1}
              strokeDasharray="3 3"
            />
          );
        })}

        {/* Case dots */}
        {cases.map((c) => {
          const x = xPos(new Date(c.created_at).getTime());
          const y = yPos(c.severity);
          const color = SEVERITY_COLOR[c.severity] ?? "#888";
          const isHovered = tooltip?.c.report_id === c.report_id;
          return (
            <g key={c.report_id}>
              {isHovered && (
                <circle cx={x} cy={y} r={DOT_R + 6} fill={color} opacity={0.2} />
              )}
              <circle
                cx={x} cy={y} r={DOT_R}
                fill={color}
                stroke={isHovered ? "#fff" : color}
                strokeWidth={isHovered ? 2 : 0}
                style={{ cursor: "pointer", filter: `drop-shadow(0 0 4px ${color}88)` }}
                onMouseEnter={(e) => setTooltip({ c, x: e.clientX, y: e.clientY })}
                onMouseMove={(e) => setTooltip({ c, x: e.clientX, y: e.clientY })}
                onClick={() => window.location.href = `/cases/${c.report_id}`}
              />
            </g>
          );
        })}

        {/* Time axis labels */}
        {timeLabels.map((tl, i) => (
          <g key={i}>
            <line
              x1={tl.x} y1={PADDING_TOP}
              x2={tl.x} y2={HEIGHT - 30}
              stroke="rgba(255,255,255,0.05)" strokeWidth={1}
            />
            <text
              x={tl.x} y={HEIGHT - 10}
              textAnchor="middle"
              fill="#555" fontSize={10}
              fontFamily="Geist Mono"
            >
              {tl.label}
            </text>
          </g>
        ))}
      </svg>

      {/* Legend */}
      <div style={{ display: "flex", gap: 20, marginTop: 16, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
        <LegendItem color="rgba(123,97,255,0.3)" label="Attack cluster (cases within 5min)" dashed />
        <LegendItem color="#888" label="Same kill chain arc" dashed />
        <LegendItem color="#888" label="Click dot to open report" />
      </div>
    </div>
  );
}

function LegendItem({ color, label, dashed }: { color: string; label: string; dashed?: boolean }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <div style={{
        width: 24, height: 2,
        background: dashed ? "transparent" : color,
        borderTop: dashed ? `2px dashed ${color}` : "none",
      }} />
      <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono" }}>{label}</span>
    </div>
  );
}

function HeatmapView({ cases }: { cases: Case[] }) {
  const HOURS = Array.from({ length: 24 }, (_, i) => i);
  const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  // Count incidents per day-of-week × hour
  const grid: number[][] = Array.from({ length: 7 }, () => Array(24).fill(0));
  for (const c of cases) {
    const d = new Date(c.created_at);
    grid[d.getDay()][d.getHours()]++;
  }

  const maxVal = Math.max(...grid.flat(), 1);

  function cellColor(val: number): string {
    if (val === 0) return "rgba(255,255,255,0.03)";
    const intensity = val / maxVal;
    if (intensity > 0.75) return "rgba(255,77,106,0.9)";
    if (intensity > 0.5) return "rgba(255,140,66,0.8)";
    if (intensity > 0.25) return "rgba(255,209,102,0.7)";
    return "rgba(123,97,255,0.5)";
  }

  return (
    <div className="card">
      <div style={{ marginBottom: 16 }}>
        <div className="card-header">Incident Heatmap — Day of Week × Hour of Day</div>
        <p style={{ fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
          Darker = more incidents. Reveals attack timing patterns.
        </p>
      </div>
      <div style={{ overflowX: "auto" }}>
        <div style={{ display: "flex", gap: 0 }}>
          {/* Day labels */}
          <div style={{ display: "flex", flexDirection: "column", gap: 0, marginRight: 8, paddingTop: 24 }}>
            {DAYS.map((day) => (
              <div key={day} style={{
                height: 32, display: "flex", alignItems: "center",
                fontSize: 11, fontFamily: "Geist Mono",
                color: "var(--text-muted)", width: 32,
              }}>{day}</div>
            ))}
          </div>

          {/* Grid */}
          <div>
            {/* Hour labels */}
            <div style={{ display: "flex", gap: 2, marginBottom: 4, paddingLeft: 0 }}>
              {HOURS.map((h) => (
                <div key={h} style={{
                  width: 28, textAlign: "center",
                  fontSize: 9, fontFamily: "Geist Mono",
                  color: "var(--text-muted)",
                }}>{h.toString().padStart(2, "0")}</div>
              ))}
            </div>

            {/* Cells */}
            {DAYS.map((day, di) => (
              <div key={day} style={{ display: "flex", gap: 2, marginBottom: 2 }}>
                {HOURS.map((h) => {
                  const val = grid[di][h];
                  return (
                    <div
                      key={h}
                      title={`${day} ${h.toString().padStart(2, "0")}:00 — ${val} incident${val !== 1 ? "s" : ""}`}
                      style={{
                        width: 28, height: 28,
                        borderRadius: 3,
                        background: cellColor(val),
                        border: "1px solid rgba(255,255,255,0.05)",
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 10, fontFamily: "Geist Mono",
                        color: val > 0 ? "rgba(255,255,255,0.8)" : "transparent",
                        cursor: val > 0 ? "default" : "default",
                        transition: "transform 0.1s",
                      }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.transform = "scale(1.2)"; }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.transform = "scale(1)"; }}
                    >
                      {val > 0 ? val : ""}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Color legend */}
      <div style={{ display: "flex", gap: 16, marginTop: 16, paddingTop: 12, borderTop: "1px solid var(--border)", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono" }}>intensity:</span>
        {[
          { color: "rgba(123,97,255,0.5)", label: "low" },
          { color: "rgba(255,209,102,0.7)", label: "medium" },
          { color: "rgba(255,140,66,0.8)", label: "high" },
          { color: "rgba(255,77,106,0.9)", label: "critical" },
        ].map((item) => (
          <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <div style={{ width: 14, height: 14, borderRadius: 2, background: item.color }} />
            <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono" }}>{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}