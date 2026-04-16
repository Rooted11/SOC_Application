const QUICK_RUNBOOK = [
  {
    title: "Investigate suspicious activity",
    steps: [
      "Open Live Feed and filter by source/event to confirm suspicious patterns.",
      "Jump to Incident Queue and sort by risk to prioritize top incidents.",
      "Use AI Analyst for triage context, then run a response playbook.",
    ],
  },
  {
    title: "Contain a high-severity incident",
    steps: [
      "Open Incident Queue and select a critical incident.",
      "Trigger response playbook and monitor action status updates.",
      "Validate containment in Live Feed and System Health.",
    ],
  },
  {
    title: "Reduce log noise safely",
    steps: [
      "Use Detections to tune thresholds and suppress known benign patterns.",
      "Use Threat Intel to ensure suppression does not hide active indicators.",
      "Validate changes in Audit Logs after deployment.",
    ],
  },
];

const TROUBLESHOOTING = [
  {
    symptom: "Buttons fail with 'Failed to fetch'",
    action: "Check backend health, CORS settings, and whether the frontend is using the correct API base URL.",
  },
  {
    symptom: "Timestamps look wrong",
    action: "Confirm logs are parsed as UTC and rendered in the configured SOC display timezone.",
  },
  {
    symptom: "Assets show as n/a",
    action: "Verify asset inventory data and ensure incoming logs include source/IP fields or asset_id mapping.",
  },
  {
    symptom: "Archive/Clear actions unavailable",
    action: "Confirm backend routes are up to date and frontend API client includes maintenance endpoints.",
  },
];

export default function HelpCenter({ setPage }) {
  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
        <div className="text-[11px] uppercase tracking-[0.35em] text-cyan-400">Operator Guide</div>
        <h2 className="mt-2 text-2xl font-semibold text-white">SOC Help Center</h2>
        <p className="mt-3 text-sm leading-7 text-slate-400 max-w-3xl">
          Use this page as your quick operational reference. It links common workflows,
          troubleshooting checks, and where to navigate next when incidents or platform
          behavior require attention.
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <button
            onClick={() => setPage?.("feed")}
            className="rounded-xl border border-cyan-500/30 bg-cyan-950/30 px-3 py-1.5 text-xs text-cyan-300 hover:bg-cyan-950/50"
          >
            Open Live Feed
          </button>
          <button
            onClick={() => setPage?.("incidents")}
            className="rounded-xl border border-orange-500/30 bg-orange-950/30 px-3 py-1.5 text-xs text-orange-300 hover:bg-orange-950/50"
          >
            Open Incident Queue
          </button>
          <button
            onClick={() => setPage?.("threats")}
            className="rounded-xl border border-red-500/30 bg-red-950/30 px-3 py-1.5 text-xs text-red-300 hover:bg-red-950/50"
          >
            Open Threat Intel
          </button>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        {QUICK_RUNBOOK.map((item) => (
          <article key={item.title} className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <h3 className="text-sm font-semibold text-white">{item.title}</h3>
            <ol className="mt-3 space-y-2 text-xs text-slate-400 list-decimal list-inside">
              {item.steps.map((step) => (
                <li key={step} className="leading-6">{step}</li>
              ))}
            </ol>
          </article>
        ))}
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <h3 className="text-sm font-semibold text-white">Troubleshooting</h3>
        <div className="mt-3 space-y-2">
          {TROUBLESHOOTING.map((item) => (
            <div key={item.symptom} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
              <div className="text-xs text-slate-200 font-medium">{item.symptom}</div>
              <div className="text-xs text-slate-400 mt-1">{item.action}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
