import { useEffect, useState } from "react";
import { api } from "../services/api";

const SEVERITY_STYLES = {
  critical: "border-rose-500/30 bg-rose-500/10 text-rose-200",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-200",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-200",
  low: "border-cyan-500/30 bg-cyan-500/10 text-cyan-200",
  info: "border-slate-700 bg-slate-800/60 text-slate-200",
};

function MetricCard({ label, value, subtext, tone = "default" }) {
  const toneClass = {
    danger: "border-rose-500/20 bg-rose-500/10",
    warning: "border-amber-500/20 bg-amber-500/10",
    accent: "border-cyan-500/20 bg-cyan-500/10",
    success: "border-emerald-500/20 bg-emerald-500/10",
    default: "border-slate-800 bg-slate-900/70",
  }[tone];

  return (
    <div className={`rounded-3xl border p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] ${toneClass}`}>
      <div className="text-[11px] uppercase tracking-[0.3em] text-slate-500">
        {label}
      </div>
      <div className="mt-3 text-4xl font-semibold tracking-tight text-white">
        {value}
      </div>
      <div className="mt-2 text-sm text-slate-400">{subtext}</div>
    </div>
  );
}

function BarList({ items, colorClass }) {
  const max = Math.max(1, ...items.map((item) => item.count));

  return (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.label} className="space-y-1">
          <div className="flex items-center justify-between text-sm">
            <span className="truncate text-slate-300">{item.label}</span>
            <span className="text-slate-500">{item.count}</span>
          </div>
          <div className="h-2 rounded-full bg-slate-800">
            <div
              className={`h-2 rounded-full ${colorClass}`}
              style={{ width: `${(item.count / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function AssetRow({ asset }) {
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 px-4 py-3">
      <div
        className={`h-2.5 w-2.5 rounded-full ${
          asset.is_isolated ? "bg-rose-400" : "bg-emerald-400"
        }`}
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-white">{asset.hostname}</div>
        <div className="text-xs uppercase tracking-[0.25em] text-slate-500">
          {asset.department} / {asset.asset_type}
        </div>
      </div>
      <div className="text-right">
        <div className="text-xs text-slate-500">{asset.ip_address}</div>
        <div className="text-xs uppercase tracking-[0.25em] text-slate-400">
          {asset.criticality}
        </div>
      </div>
    </div>
  );
}

export default function Dashboard({ lastUpdated, showAlert }) {
  const [overview, setOverview] = useState(null);
  const [logStats, setLogStats] = useState(null);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    Promise.all([api.getOverview(), api.getLogStats(), api.getAssets()])
      .then(([overviewData, logData, assetData]) => {
        if (cancelled) return;
        setOverview(overviewData);
        setLogStats(logData);
        setAssets(assetData.assets || []);
      })
      .catch((error) => {
        if (!cancelled) showAlert(error.message, "error");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [lastUpdated, showAlert]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center rounded-3xl border border-slate-800 bg-slate-900/60 text-slate-500">
        Loading command center...
      </div>
    );
  }

  const headline = overview?.headline || {};
  const response = overview?.response || {};
  const assetSummary = overview?.assets || {};
  const intel = overview?.intel || {};
  const topEvents = (overview?.top_event_types || []).map((item) => ({
    label: item.event_type,
    count: item.count,
  }));
  const hotAssets = (overview?.hot_assets || []).map((item) => ({
    label: item.hostname,
    count: item.count,
  }));
  const recentIncidents = overview?.recent_incidents || [];
  const highestRiskAsset = assets.find((asset) => asset.criticality === "critical") || assets[0];

  return (
    <div className="space-y-6">
      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(320px,0.8fr)]">
        <div className="overflow-hidden rounded-[28px] border border-cyan-500/20 bg-[linear-gradient(135deg,rgba(14,165,233,0.16),rgba(15,23,42,0.9)_42%,rgba(2,6,23,1))] p-7 shadow-[0_20px_80px_rgba(8,47,73,0.32)]">
          <div className="text-[11px] uppercase tracking-[0.35em] text-cyan-300/80">
            Mission Status
          </div>
          <div className="mt-4 flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="text-6xl font-semibold tracking-tight text-white">
                {headline.posture_score ?? 0}
              </div>
              <div className="mt-2 text-sm uppercase tracking-[0.3em] text-slate-300">
                Posture score
              </div>
            </div>

            <div className="grid flex-1 gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <div className="text-[11px] uppercase tracking-[0.3em] text-slate-400">
                  Open cases
                </div>
                <div className="mt-3 text-3xl font-semibold text-white">
                  {headline.open_incidents ?? 0}
                </div>
              </div>
              <div className="rounded-2xl border border-rose-400/20 bg-rose-500/10 p-4">
                <div className="text-[11px] uppercase tracking-[0.3em] text-rose-200/80">
                  Critical
                </div>
                <div className="mt-3 text-3xl font-semibold text-white">
                  {headline.critical_open ?? 0}
                </div>
              </div>
              <div className="rounded-2xl border border-orange-400/20 bg-orange-500/10 p-4">
                <div className="text-[11px] uppercase tracking-[0.3em] text-orange-200/80">
                  High
                </div>
                <div className="mt-3 text-3xl font-semibold text-white">
                  {headline.high_open ?? 0}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 grid gap-4 text-sm text-slate-300 md:grid-cols-3">
            <div className="rounded-2xl border border-slate-700/70 bg-slate-950/30 p-4">
              <div className="text-[11px] uppercase tracking-[0.3em] text-slate-500">
                Telemetry 24h
              </div>
              <div className="mt-2 text-2xl font-semibold text-white">
                {headline.recent_logs_24h ?? 0}
              </div>
              <div className="mt-1 text-slate-400">
                {headline.recent_anomalies_24h ?? 0} anomalous events surfaced
              </div>
            </div>
            <div className="rounded-2xl border border-slate-700/70 bg-slate-950/30 p-4">
              <div className="text-[11px] uppercase tracking-[0.3em] text-slate-500">
                Automation
              </div>
              <div className="mt-2 text-2xl font-semibold text-white">
                {response.automation_rate_pct ?? 0}%
              </div>
              <div className="mt-1 text-slate-400">Incidents touched by playbooks</div>
            </div>
            <div className="rounded-2xl border border-slate-700/70 bg-slate-950/30 p-4">
              <div className="text-[11px] uppercase tracking-[0.3em] text-slate-500">
                Response
              </div>
              <div className="mt-2 text-2xl font-semibold text-white">
                {response.containment_rate_pct ?? 0}%
              </div>
              <div className="mt-1 text-slate-400">Contained or resolved cases</div>
            </div>
          </div>
        </div>

        <div className="rounded-[28px] border border-slate-800 bg-slate-900/70 p-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
                Threat pressure
              </div>
              <div className="mt-2 text-2xl font-semibold text-white">
                {intel.active_iocs ?? 0} active indicators
              </div>
            </div>
            <div className="rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs uppercase tracking-[0.25em] text-amber-200">
              {intel.critical_iocs ?? 0} elevated
            </div>
          </div>

          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            <MetricCard
              label="Avg resolution"
              value={`${response.avg_resolution_hours ?? 0}h`}
              subtext="Mean time to resolve"
              tone="accent"
            />
            <MetricCard
              label="Resolved"
              value={response.resolved_incidents ?? 0}
              subtext="Closed incidents on record"
              tone="success"
            />
          </div>

          <div className="mt-5 rounded-3xl border border-slate-800 bg-slate-950/60 p-5">
            <div className="text-[11px] uppercase tracking-[0.3em] text-slate-500">
              Log health
            </div>
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div>
                <div className="text-3xl font-semibold text-white">
                  {logStats?.total_logs ?? 0}
                </div>
                <div className="mt-1 text-sm text-slate-400">events ingested</div>
              </div>
              <div>
                <div className="text-3xl font-semibold text-white">
                  {logStats?.anomaly_rate_pct ?? 0}%
                </div>
                <div className="mt-1 text-sm text-slate-400">anomaly rate</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Total assets"
          value={assetSummary.total ?? 0}
          subtext="Hosts and infrastructure under watch"
        />
        <MetricCard
          label="Critical assets"
          value={assetSummary.critical ?? 0}
          subtext="Systems with highest blast radius"
          tone="warning"
        />
        <MetricCard
          label="Isolated assets"
          value={assetSummary.isolated ?? 0}
          subtext={`${assetSummary.isolation_rate_pct ?? 0}% currently quarantined`}
          tone="danger"
        />
        <MetricCard
          label="Anomalous logs"
          value={logStats?.anomalous_logs ?? 0}
          subtext={`Average risk ${logStats?.avg_risk_score ?? 0}/100`}
          tone="accent"
        />
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="rounded-[28px] border border-slate-800 bg-slate-900/70 p-6">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
                  Attack patterns
                </div>
                <div className="mt-2 text-xl font-semibold text-white">
                  Most active event types
                </div>
              </div>
            </div>
            {topEvents.length > 0 ? (
              <BarList items={topEvents} colorClass="bg-cyan-400" />
            ) : (
              <div className="text-sm text-slate-500">No telemetry yet.</div>
            )}
          </div>

          <div className="rounded-[28px] border border-slate-800 bg-slate-900/70 p-6">
            <div className="mb-5">
              <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
                Exposure map
              </div>
              <div className="mt-2 text-xl font-semibold text-white">
                Assets seeing the most incident volume
              </div>
            </div>
            {hotAssets.length > 0 ? (
              <BarList items={hotAssets} colorClass="bg-orange-400" />
            ) : (
              <div className="text-sm text-slate-500">No hot assets identified yet.</div>
            )}

            {highestRiskAsset && (
              <div className="mt-6 rounded-3xl border border-slate-800 bg-slate-950/60 p-4">
                <div className="text-[11px] uppercase tracking-[0.3em] text-slate-500">
                  Priority asset
                </div>
                <div className="mt-3 text-lg font-semibold text-white">
                  {highestRiskAsset.hostname}
                </div>
                <div className="mt-1 text-sm text-slate-400">
                  {highestRiskAsset.department} / {highestRiskAsset.ip_address}
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="rounded-[28px] border border-slate-800 bg-slate-900/70 p-6">
          <div className="mb-5">
            <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
              Watchlist
            </div>
            <div className="mt-2 text-xl font-semibold text-white">
              Asset readiness
            </div>
          </div>
          <div className="space-y-3">
            {assets.slice(0, 6).map((asset) => (
              <AssetRow key={asset.id} asset={asset} />
            ))}
            {assets.length === 0 && (
              <div className="text-sm text-slate-500">No assets available.</div>
            )}
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="rounded-[28px] border border-slate-800 bg-slate-900/70 p-6">
          <div className="mb-5">
            <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
              Active queue
            </div>
            <div className="mt-2 text-xl font-semibold text-white">
              Latest incidents
            </div>
          </div>

          <div className="space-y-3">
            {recentIncidents.map((incident) => (
              <div
                key={incident.id}
                className="rounded-3xl border border-slate-800 bg-slate-950/60 p-4"
              >
                <div className="flex flex-wrap items-center gap-3">
                  <div className="text-lg font-semibold text-white">
                    #{incident.id}
                  </div>
                  <span
                    className={`rounded-full border px-3 py-1 text-xs uppercase tracking-[0.25em] ${
                      SEVERITY_STYLES[incident.severity] || SEVERITY_STYLES.info
                    }`}
                  >
                    {incident.severity}
                  </span>
                  <span className="text-xs uppercase tracking-[0.25em] text-slate-500">
                    {incident.status}
                  </span>
                  <span className="ml-auto text-sm text-slate-400">
                    {Math.round(incident.risk_score || 0)}/100 risk
                  </span>
                </div>
                <div className="mt-3 text-sm text-slate-200">{incident.title}</div>
                <div className="mt-2 text-xs text-slate-500">
                  {incident.created_at
                    ? new Date(incident.created_at).toLocaleString()
                    : "Unknown timestamp"}
                </div>
              </div>
            ))}
            {recentIncidents.length === 0 && (
              <div className="text-sm text-slate-500">No incidents recorded yet.</div>
            )}
          </div>
        </div>

        <div className="rounded-[28px] border border-slate-800 bg-slate-900/70 p-6">
          <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
            Analyst notes
          </div>
          <div className="mt-2 text-xl font-semibold text-white">
            What needs attention now
          </div>

          <div className="mt-5 space-y-4 text-sm text-slate-300">
            <div className="rounded-3xl border border-slate-800 bg-slate-950/60 p-4">
              Focus on the {headline.critical_open ?? 0} critical cases first. They are
              the largest drag on the current posture score.
            </div>
            <div className="rounded-3xl border border-slate-800 bg-slate-950/60 p-4">
              Automation has covered {response.automation_rate_pct ?? 0}% of incidents.
              Raising that number is the fastest path to a steadier queue.
            </div>
            <div className="rounded-3xl border border-slate-800 bg-slate-950/60 p-4">
              {intel.critical_iocs ?? 0} high-priority indicators are active in the feed.
              Cross-check them against unresolved incidents and exposed assets.
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
