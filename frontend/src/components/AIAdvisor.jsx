import { useEffect, useRef, useState } from "react";
import { api } from "../services/api";

const SEV_BORDER = {
  critical: "border-red-800 bg-red-900/20",
  high: "border-orange-800 bg-orange-900/20",
  medium: "border-yellow-800 bg-yellow-900/20",
  low: "border-blue-800 bg-blue-900/20",
  info: "border-gray-700 bg-gray-800/20",
};

const QUICK_PROMPTS = [
  { label: "Containment plan", query: "Give me a step-by-step containment plan for this incident" },
  { label: "Root cause analysis", query: "What is the probable root cause and kill chain for this incident?" },
  { label: "Executive report", query: "__REPORT__" },
  { label: "MITRE ATT&CK mapping", query: "Map this incident to MITRE ATT&CK TTPs with technique IDs" },
  { label: "IOC investigation", query: "How should I investigate the IOC matches in this incident?" },
  { label: "Escalation criteria", query: "When should I escalate this incident and to whom?" },
];

function TypingIndicator() {
  return (
    <div className="flex items-center gap-1.5 text-green-500">
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-green-500" style={{ animationDelay: "0ms" }} />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-green-500" style={{ animationDelay: "150ms" }} />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-green-500" style={{ animationDelay: "300ms" }} />
      <span className="ml-2 text-xs text-gray-500">Claude is analysing...</span>
    </div>
  );
}

export default function AIAdvisor({ lastUpdated, showAlert }) {
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [selected, setSelected] = useState(null);
  const [query, setQuery] = useState("");
  const [messages, setMessages] = useState([]);
  const [thinking, setThinking] = useState(false);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const chatEndRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    api.getIncidents({ limit: 30, status: "open" })
      .then((response) => {
        if (cancelled) return;
        const list = response.incidents || [];
        setIncidents(list);

        if (list.length === 0) {
          setSelectedId(null);
          setSelected(null);
          return;
        }

        const nextId = list.some((incident) => incident.id === selectedId)
          ? selectedId
          : list[0].id;
        setSelectedId(nextId);
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
  }, [lastUpdated, selectedId, showAlert]);

  useEffect(() => {
    if (!selectedId) return;

    let cancelled = false;
    setDetailLoading(true);

    api.getIncident(selectedId)
      .then((incident) => {
        if (!cancelled) setSelected(incident);
      })
      .catch((error) => {
        if (!cancelled) showAlert(error.message, "error");
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [selectedId, showAlert]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, thinking]);

  function selectIncident(incidentId) {
    setSelectedId(incidentId);
    setMessages([]);
    setQuery("");
  }

  async function sendQuery(overrideQuery) {
    const rawQuery = overrideQuery || query;
    const trimmed = rawQuery.trim();
    if (!trimmed || !selected) return;

    const displayQuery =
      trimmed === "__REPORT__" ? "Generate an executive incident report" : trimmed;

    setQuery("");
    setMessages((prev) => [...prev, { role: "user", content: displayQuery }]);
    setThinking(true);

    try {
      const response = trimmed === "__REPORT__"
        ? await api.aiReport(selected.id)
        : await api.aiQuery(selected.id, trimmed);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: trimmed === "__REPORT__" ? response.report : response.response,
        },
      ]);
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        { role: "error", content: `Error: ${error.message}` },
      ]);
      showAlert(error.message, "error");
    } finally {
      setThinking(false);
    }
  }

  function handleKey(event) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendQuery();
    }
  }

  return (
    <div className="flex h-full min-h-0 gap-5">
      <div className="flex w-72 flex-shrink-0 flex-col gap-2">
        <div className="mb-1 text-xs uppercase tracking-widest text-gray-500">
          Open Incidents
        </div>
        <div className="flex-1 space-y-1.5 overflow-auto pr-1">
          {loading ? (
            <div className="animate-pulse text-sm text-gray-600">Loading...</div>
          ) : incidents.length === 0 ? (
            <div className="text-sm text-gray-600">No open incidents.</div>
          ) : (
            incidents.map((incident) => (
              <button
                key={incident.id}
                onClick={() => selectIncident(incident.id)}
                className={`w-full rounded border p-3 text-left transition-colors ${
                  selectedId === incident.id
                    ? "border-green-700 bg-green-900/20"
                    : `${SEV_BORDER[incident.severity] || SEV_BORDER.info} hover:border-gray-600`
                }`}
              >
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-xs text-gray-500">#{incident.id}</span>
                  <span className="font-mono text-xs text-gray-400">
                    {Math.round(incident.risk_score)}/100
                  </span>
                </div>
                <p className="line-clamp-2 text-xs leading-relaxed text-gray-300">
                  {incident.title}
                </p>
                <div className="mt-1 text-xs capitalize text-gray-600">
                  {incident.severity}
                </div>
              </button>
            ))
          )}
        </div>
      </div>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-3">
        {selected && (
          <div className={`flex-shrink-0 rounded border p-3 ${SEV_BORDER[selected.severity] || SEV_BORDER.info}`}>
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-widest text-gray-500">
                Active Context
              </span>
              <span className="ml-auto font-mono text-xs text-gray-400">
                Risk {Math.round(selected.risk_score)}/100 / {selected.severity}
              </span>
            </div>
            <p className="mt-1 text-sm font-medium text-gray-200">{selected.title}</p>
            {selected.description && (
              <p className="mt-0.5 line-clamp-2 text-xs text-gray-500">
                {selected.description}
              </p>
            )}
            {selected.trigger_log && (
              <div className="mt-2 rounded border border-gray-800 bg-gray-950/60 px-3 py-2 text-xs text-gray-400">
                {selected.trigger_log.event_type || "unknown"} / {selected.trigger_log.ip_src || "n/a"} / {selected.trigger_log.user || "n/a"}
              </div>
            )}
          </div>
        )}

        {detailLoading && (
          <div className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-500">
            Refreshing incident context...
          </div>
        )}

        {selected?.ai_recommendation && messages.length === 0 && (
          <div className="flex-shrink-0 rounded-lg border border-gray-800 bg-gray-900 p-4">
            <div className="mb-2 text-xs uppercase tracking-widest text-gray-500">
              Auto-generated Recommendation
            </div>
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-green-400">
              {selected.ai_recommendation}
            </pre>
          </div>
        )}

        <div className="flex flex-wrap gap-1.5 flex-shrink-0">
          {QUICK_PROMPTS.map((prompt) => (
            <button
              key={prompt.label}
              onClick={() => sendQuery(prompt.query)}
              disabled={thinking || !selected}
              className="rounded-full border border-gray-700 bg-gray-800 px-3 py-1 text-xs text-gray-400 transition-colors hover:border-green-700 hover:text-green-400 disabled:opacity-30"
            >
              {prompt.label}
            </button>
          ))}
        </div>

        <div className="min-h-0 flex-1 overflow-auto rounded-lg border border-gray-800 bg-gray-950 p-4">
          {messages.length === 0 && !thinking ? (
            <div className="flex h-full items-center justify-center text-sm text-gray-700">
              {selected
                ? "Select a quick prompt or type a question below"
                : "Select an incident to begin analysis"}
            </div>
          ) : (
            <div className="space-y-4">
              {messages.map((message, index) => (
                <div key={index} className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}>
                  {message.role === "user" ? (
                    <div className="max-w-[75%] rounded-2xl rounded-tr-sm border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-gray-300">
                      {message.content}
                    </div>
                  ) : message.role === "error" ? (
                    <div className="max-w-[90%] rounded-2xl border border-red-800 bg-red-950 px-4 py-2 text-sm text-red-400">
                      {message.content}
                    </div>
                  ) : (
                    <div className="w-full max-w-[90%]">
                      <div className="mb-1.5 text-xs uppercase tracking-widest text-green-600">
                        Claude AI
                      </div>
                      <pre className="whitespace-pre-wrap rounded-2xl border border-gray-800 bg-gray-900 px-4 py-3 font-sans text-sm leading-relaxed text-gray-300">
                        {message.content}
                      </pre>
                    </div>
                  )}
                </div>
              ))}

              {thinking && (
                <div className="flex justify-start">
                  <div className="rounded-2xl border border-gray-800 bg-gray-900 px-4 py-3">
                    <TypingIndicator />
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>
          )}
        </div>

        <div className="flex flex-shrink-0 gap-2">
          <textarea
            rows={1}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={handleKey}
            placeholder={selected ? "Ask Claude anything about this incident... (Enter to send)" : "Select an incident first"}
            disabled={!selected}
            className="flex-1 resize-none rounded-lg border border-gray-700 bg-gray-900 px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:border-green-700 focus:outline-none disabled:opacity-40"
          />
          <button
            onClick={() => sendQuery()}
            disabled={thinking || !query.trim() || !selected}
            className="flex-shrink-0 rounded-lg border border-green-800 bg-green-900/40 px-5 py-2.5 text-sm text-green-400 transition-colors hover:bg-green-900/70 disabled:opacity-30"
          >
            {thinking ? "..." : "Send"}
          </button>
        </div>

        {messages.length > 0 && (
          <button
            onClick={() => setMessages([])}
            className="self-start text-xs text-gray-600 hover:text-gray-400"
          >
            Clear chat
          </button>
        )}
      </div>
    </div>
  );
}
